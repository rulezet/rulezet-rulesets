rule SIGNATURE_BASE_PUA_VULN_Driver_Powertool_Kevpsys_Powertool_8E63: FILE {
  meta:
    description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - kEvP64.sys"
    author      = "Florian Roth"
    id          = "0010c121-11bb-5068-a06d-aa136e5af0ad"
    date        = "2023-06-14"
    modified    = "2023-12-05"
    reference   = "https://github.com/magicsword-io/LOLDrivers"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/yara-rules_vuln_drivers_strict.yar#L3090-L3112"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "8e6363a6393eb4234667c6f614b2072e33512866b3204f8395bbe01530d63f2f"
    hash        = "09b0e07af8b17db1d896b78da4dd3f55db76738ee1f4ced083a97d737334a184"
    hash        = "1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c"
    logic_hash  = "eb30a51b174462ff2b1b3d62b62fc572445293dfdc0f70f64c73c9b15cbf6c0b"
    score       = 40
    quality     = 85
    tags        = "FILE"

  strings:
    $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 50 00 6f 00 77 00 65 00 72 00 54 00 6f 00 6f 00 6c }
    $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 50 00 6f 00 77 00 65 00 72 00 54 00 6f 00 6f 00 6c }
    $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 2e 00 30 00 20 00 62 00 75 00 69 00 6c 00 74 00 20 00 62 00 79 00 3a 00 20 00 57 00 69 00 6e 00 44 00 44 00 4b }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 2e 00 30 }
    $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 6b 00 45 00 76 00 50 00 36 00 34 00 2e 00 73 00 79 00 73 }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 50 00 6f 00 77 00 65 00 72 00 54 00 6f 00 6f 00 6c }
    $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 6b 00 45 00 76 00 50 00 36 00 34 00 2e 00 73 00 79 00 73 }
    $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 50 00 6f 00 77 00 65 00 72 00 54 00 6f 00 6f 00 6c }

  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}