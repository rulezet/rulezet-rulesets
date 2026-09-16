rule sig_20160315_e24b555e17d9f33b8b42cad349da63ca {
  meta:
    description = "datamaliciousorder - file 20160315_e24b555e17d9f33b8b42cad349da63ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "571731be38dfe38d2c18c7c95acc67394a67fbeba409a607f37eb48f0d10f3ed"

  strings:
    $s1 = "function BOgB(XuaZAWtVnTIu){WshShell[VkR + unmU](XuaZAWtVnTIu, 0, 0);}" fullword ascii
    $s2 = "while (YPSLtMbtnBbznCV.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = " + bXnXnBWC + sunndYXHfxHR, false);" fullword ascii
    $s4 = "function oBsxtAJMq(n){return EislXYYhHyUDU + ZfkH + EmJp + XXpdLoyojdWbL + ulRWlB + cvoGToFzCv + rgUlsF + yrFkUF;}" fullword ascii
    $s5 = "var PGNOueHnacJ = new Date();" fullword ascii
    $s6 = "YPSLtMbtnBbznCV[vUyWfKGHsDR + FMaYaUegyJvZgL](UkYS, gWMoMFIVXQHQuMM + joWaDtVMK + ebkjubfp + pFtqkEWqg + LvHlupYSRGHK + OIAkjviu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}