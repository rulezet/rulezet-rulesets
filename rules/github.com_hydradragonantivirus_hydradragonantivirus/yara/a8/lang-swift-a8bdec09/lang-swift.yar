rule lang_swift {
  meta:
    description = "Identify a Swift binary regardless of targetting Apple platforms."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.01.14"
    DaysofYARA  = "14/100"

  strings:
    $swift = "__swift"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    #swift >= 4
}