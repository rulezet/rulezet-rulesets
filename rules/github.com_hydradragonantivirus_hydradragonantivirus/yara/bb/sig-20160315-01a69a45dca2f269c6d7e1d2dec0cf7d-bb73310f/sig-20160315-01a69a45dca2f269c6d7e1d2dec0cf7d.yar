rule sig_20160315_01a69a45dca2f269c6d7e1d2dec0cf7d {
  meta:
    description = "datamaliciousorder - file 20160315_01a69a45dca2f269c6d7e1d2dec0cf7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "927fa56665fb9946bc781f257265558247dee9f06025ad1e3f1f6ae5057be39f"

  strings:
    $s1 = "function RDqLi(lQlDskg){WshShell[anhRB + STZYbnh](lQlDskg, 0, 0);}" fullword ascii
    $s2 = "while (Rdu0.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function AyXygvUdW(n){return tOhlSy + WcKRULXCEpfc + cJdvaSMpNsk + KJUIQoNVkci + JOMnxWrao + rLkpkZlDDF + yiA;}" fullword ascii
    $s4 = " + srQJhXqdJX + vQhaIUezHylBAVM, false);" fullword ascii
    $s5 = "Rdu0[ukIejziYDq + EkTusrkJqdl](KuJWybXJYhyvfF + HhsIEUBH, TcaqG + aKTTdnKu + YyrfcDJkTOoPuHB + ufDgQMMMM + ZEWImLKEIJX + dQQshSS" ascii
    $s6 = "var hDU = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}