rule PUA_VULN_Driver_Dell_Dellinstrumentation_BC26 {
  meta:
    description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - dellinstrumentation.sys"
    author      = "Florian Roth"
    reference   = "https://github.com/magicsword-io/LOLDrivers"
    hash        = "bc2606740e4648c3732541db929f2e02ea8567520d35de57c671e93c71e632f3"
    date        = "2025-03-07"
    score       = 40

  strings:
    $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 44 00 65 00 6c 00 6c 00 49 00 6e 00 73 00 74 00 72 00 75 00 6d 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e }  
    $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 44 00 65 00 6c 00 6c }  
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 32 00 2e 00 38 00 2e 00 39 00 2e 00 34 }  
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 44 00 65 00 6c 00 6c 00 49 00 6e 00 73 00 74 00 72 00 75 00 6d 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e }  
    $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 a9 00 20 00 32 00 30 00 32 00 33 00 20 00 44 00 65 00 6c 00 6c 00 20 00 49 00 6e 00 63 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 52 00 69 00 67 00 68 00 74 00 73 00 20 00 52 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 20 }  

  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}