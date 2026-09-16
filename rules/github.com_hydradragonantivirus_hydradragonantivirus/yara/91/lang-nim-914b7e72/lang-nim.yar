rule lang_nim {
  meta:
    description = "Identify a Nim binary regardless of format (PE, Macho, ELF) or arch."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.01.03"
    sample      = "8ec44187e50c15a7c4c89af4a1e99c63c855539101ec1ef4588d2e12e05f7d2b"      DaysofYARA  = "3/100"

  strings:
    $nim = "@nim"

  condition:
    (
      int16(0) == 0x5a4d or        uint32(0) == 0x464c457f or        uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    #nim > 4
}