rule sig_20160218_522163d19948eebb6dddac4361774f16 {
  meta:
    description = "datamaliciousorder - file 20160218_522163d19948eebb6dddac4361774f16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff6ca71fb42c907461240b7ddaa6bd527e55817a6e16dd6dd47ca2cc3e2493b"

  strings:
    $s1 = "var a21='555C535E0508010724011C1405101001070C4A070B095E3C5E170D0A030801090B09020D0A050A070D05084A070B095E17565E555051515C565C545" ascii
    $s2 = " };'+s83+y3;this[h66](x18);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}