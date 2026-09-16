rule ARKBIRD_SOLG_APT_Turla_Ironpython_Apr_2021_1: FILE {
  meta:
    description = "Detect IronPython script used by Turla group"
    author      = "Arkbird_SOLG"
    id          = "303929d4-2c43-5e43-aeb0-09f469f7091b"
    date        = "2021-04-30"
    modified    = "2021-05-01"
    reference   = "https://twitter.com/DrunkBinary/status/1388332507695919104"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-05-01/Turla/APT_Turla_IronPython_Apr_2021_1.yara#L1-L26"
    license_url = "N/A"
    logic_hash  = "f6b626cddb4832f842a15eddce705fb24125e4341c425cf27dbbe537e2a98bdc"
    score       = 75
    quality     = 57
    tags        = "FILE"
    hash1       = "65b43e30547ae4066229040c9056aa9243145b9ae5f3b9d0a01a5068ef9a0361"
    hash2       = "c430ebab4bf827303bc4ad95d40eecc7988bdc17cc139c8f88466bc536755d4e"
    hash3       = "f76257749792cc4e54f75d0e7a83e7a4429395c5dbc48078a8068575d7e9a98"
    tlp         = "White"
    adversary   = "Turla"

  strings:
    $s1  = "lambda s,k:''.join([chr((ord(c)^k)%0x100) for c in s])"
    $s2  = "from System.Security.Cryptography import*"
    $s3  = "RijndaelManaged(KeySize=128,BlockSize=128)"
    $s4  = "return System.Array[System.Byte]([ord(x)for x in list(str)])"
    $s5  = { 53 79 73 74 65 6d 2e 41 72 72 61 79 2e 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 28 53 79 73 74 65 6d 2e 42 79 74 65 2c [10-12] 2e 4c 65 6e 67 74 68 29 }
    $s6  = { 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 [4-10] 5b 31 36 3a 5d 29 2c 73 79 73 2e 61 72 67 76 5b 31 5d 2c [4-10] 5b 3a 31 36 5d 2c }
    $s7  = "Assembly.Load("
    $s8  = " if len(sys.argv)!=2:"
    $s9  = "except System.SystemException as ex:"
    $s10 = "if __name__=="
    $s11 = ".format(ex.Message,ex.StackTrace))"

  condition:
    filesize > 100KB and 9 of ($s*)
}