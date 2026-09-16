rule info_macho_python {
  meta:
    description = "Identify Mach-O executables with bundled python content."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.31"
    references  = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
    sample      = "1153fca0b395b3f219a6ec7ecfc33f522e7b8fc6676ecb1e40d1827f43ad22be"
    DaysofYARA  = "90/100"

  strings:
    $s0 = "@_Py"
    $s1 = "@executable_path/Python"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    #s0 > 10 or $s1
}