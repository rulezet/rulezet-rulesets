rule SUSP_Macho_Bin_Ref_kextunload {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-05"
    version     = "1.0"
    description = "check Macho files for the reference to file under /bin/ like kextunload"

  strings:
    $ = "bin/kextunload" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      )
    and all of them
}