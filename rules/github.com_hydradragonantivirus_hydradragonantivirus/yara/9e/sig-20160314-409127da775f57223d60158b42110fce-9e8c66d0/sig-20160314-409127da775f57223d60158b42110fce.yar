rule sig_20160314_409127da775f57223d60158b42110fce {
  meta:
    description = "datamaliciousorder - file 20160314_409127da775f57223d60158b42110fce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44f5372f50cd97896634fbcf3c56e8395935ab9427788f54666eafd45d3765f6"

  strings:
    $s1 = "zdArpMeBWCvQlLI.open(vPTV + wVenSr + KyS, gKagWFUUnMr + iHXXIALDx + BBjUbQfDZJqvY + UyNDTjTKNhs + VOfsoUn + bYzdwWMCUKEui + KbsI" ascii
    $s2 = "while (zdArpMeBWCvQlLI.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return bTcppKwG + dkrI + ntTUQzE + JvcoogLyD + zRmOBdcxigIucH + XKFqgQWuKvsWm + DeUdbmYfzktSh" fullword ascii
    $s4 = " + gQbG + JqX + JIz, false);" fullword ascii
    $s5 = "function kDPEOg(n)" fullword ascii
    $s6 = "var xILF = new Date();" fullword ascii
    $s7 = "function CHDIiukfReV(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}