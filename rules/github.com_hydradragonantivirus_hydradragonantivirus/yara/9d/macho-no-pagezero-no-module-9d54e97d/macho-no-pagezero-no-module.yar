rule macho_no_pagezero_no_module {
  meta:
    description = "Identify macho executable without a __PAGEZERO segment without the module module."
    author      = "@shellcromancer"
    version     = "1.2"
    date        = "2023.03.02"
    sample      = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197"      DaysofYARA  = "61/100"

  strings:
    $segment1 = "__PAGEZERO"
    $segment2 = "__ZERO"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    uint32(0xc) == 0x2 and      not $segment1 in (0..uint32(0x14)) and      not $segment2 in (0..uint32(0x14))
}