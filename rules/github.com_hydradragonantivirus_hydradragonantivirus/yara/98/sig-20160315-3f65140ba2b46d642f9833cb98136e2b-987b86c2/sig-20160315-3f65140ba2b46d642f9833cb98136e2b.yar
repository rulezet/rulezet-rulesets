rule sig_20160315_3f65140ba2b46d642f9833cb98136e2b {
  meta:
    description = "datamaliciousorder - file 20160315_3f65140ba2b46d642f9833cb98136e2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c475b0e99d3357b26121b7156e0ab482ee0357d1f7a8719088d6ee7b39ffe4a4"

  strings:
    $s1 = "function UgTG(VukPBZZsBaxzV){WshShell[LidPSSsWrfvY + IdJHkfc + LXLLMKCv](VukPBZZsBaxzV, 0, 0);}" fullword ascii
    $s2 = "while (apKt.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function lJnzrjXY(n){return NzFfFHmpm + srBdzfppCcBjzIY + pdsrnSPjPzGZfNl + AOTMKgXquH + WJThE + fLobuPGyurH;}" fullword ascii
    $s4 = "CFeHL + ZYLvljGuMhq + JqQS + PpUZj, false);" fullword ascii
    $s5 = "apKt[SDogTnGgqd + LIipxmMF](umuh, bxUDqYjXnBaoSoT + VTIqJM + bvG1 + SqUI + uYhljFI + dADhnKBcNqXuKNN + dBzzqePkh + cJySEDOkENM +" ascii
    $s6 = "var fMFtWkRALT = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}