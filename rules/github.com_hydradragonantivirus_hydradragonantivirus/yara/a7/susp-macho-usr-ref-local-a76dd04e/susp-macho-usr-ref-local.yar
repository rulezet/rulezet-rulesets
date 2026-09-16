rule SUSP_Macho_Usr_Ref_local {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-06"
    version     = "1.0"
    description = "check Macho files for the reference to file under /usr/ like local "

  strings:
    $ = "usr/local" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      )
    and all of them
}