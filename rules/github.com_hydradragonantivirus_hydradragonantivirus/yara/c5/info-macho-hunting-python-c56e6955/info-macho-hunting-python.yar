rule INFO_Macho_Hunting_Python {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for additional execution strings like python"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"

  strings:
    $str = "python" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and all of them
}