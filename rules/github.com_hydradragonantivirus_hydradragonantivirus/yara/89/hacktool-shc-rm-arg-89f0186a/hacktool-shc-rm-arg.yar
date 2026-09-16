rule hacktool_shc_rm_arg {
  meta:
    description   = "Identify executables built with the shc compiler using the rmargs function"
    author        = "@shellcromancer"
    version       = "1.1"
    last_modified = "2023.02.01"
    reference     = "https://neurobin.org/projects/softwares/unix/shc/"
    reference     = "https://asec.ahnlab.com/en/45182/"
    sample        = "d2626acc7753a067014f9d5726f0e44ceba1063a1cd193e7004351c90875f071"
    DaysofYARA    = "23/100"
    DaysofYARA    = "32/100"

  strings:
    $rmargs = {
      48 83 7D F8 00        74 ??                 48 8B 45 F8           48 8B 00              48 85 C0              74 ??                 48 8B 45 F8           48 8B 00              48 3B 45 F0           75 ??                 EB ??                 48 8B 45 F8           48 83 C0 08           48 8B 10              48 8B 45 F8           48 89 10              48 83 45 F8 08        48 83 7D F8 00        74 ??                 48 8B 45 F8           48 8B 00              48 85 C0            }

    $clang_0x10000357e = {
      48 83 7d f8 00        88 45 ef              0f 84 [4]             48 8b 4d f8           31 c0                 48 83 39 00           88 45 ef              0f 84 [4]             48 8b 45 f8           48 8b 00              48 3b 45 f0           0f 95 c0              88 45 ef              8a 45 ef              a8 01                 0f 85 [4]             e9 [4]                e9 [4]                48 8b 45 f8           48 83 c0 08           48 89 45 f8           e9 [4]                e9 [4]                31 c0                 48 83 7d f8 00        88 45 ee              0f 84 [4]             48 8b 45 f8           48 83 38 00           0f 95 c0              88 45 ee              8a 45 ee              a8 01                 0f 85 [4]             e9 [4]                48 8b 45 f8           48 8b 48 08           48 8b 45 f8         }

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    any of them
}