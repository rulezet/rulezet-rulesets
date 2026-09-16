rule Mimikatz_Samples_2014b_2 {
  meta:
    description = "Mimikatz pwassword dumper samples from the second half of 2014"
    author      = "Florian Roth with the help of YarGen Rule Generator"
    reference   = "not set"
    date        = "2014/12/23"
    score       = 80
    hash        = "98033f5bbdd79b12a7804bad0698c91e6d5067ad"

  strings:
    $s0  = "0: kd> .process /r /p <EPROCESS address>" fullword ascii
    $s4  = "%p - lsasrv!LogonSessionListCount" fullword ascii
    $s7  = "%p - lsasrv!LogonSessionList" fullword ascii
    $s12 = "livessp!LiveGlobalLogonSessionList" fullword ascii
    $s13 = "UndefinedLogonType" fullword ascii
    $s14 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii
    $s15 = "masterkey" fullword ascii
    $s16 = "kerberos!KerbGlobalLogonSessionTable" fullword ascii
    $s17 = "RemoteInteractive" fullword ascii
    $s18 = "mimilib.dll" fullword wide
    $s19 = "%p - lsasrv!InitializationVector" fullword ascii
    $s20 = "lsasrv!LogonSessionListCount" fullword ascii

  condition:
    all of them
}