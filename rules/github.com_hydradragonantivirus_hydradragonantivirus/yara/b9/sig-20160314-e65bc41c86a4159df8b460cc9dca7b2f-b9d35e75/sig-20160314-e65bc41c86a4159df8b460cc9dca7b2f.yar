rule sig_20160314_e65bc41c86a4159df8b460cc9dca7b2f {
  meta:
    description = "datamaliciousorder - file 20160314_e65bc41c86a4159df8b460cc9dca7b2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61fc60a5c17e7a856c1fd3a05a4504f3c68343a789685f6edbe9a311efe3c5e7"

  strings:
    $s1 = "pFhwyrUnmm.open(nca, AjxXaVVSC + lmXbfLYF + Dmw + mgQBYAxRO + teYAVxJGZlGgSdG + TDwLEagbSBEIc + DyTONKmKfouZNmq + TtqtNAPLuvnO +" ascii
    $s2 = "while (pFhwyrUnmm.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return hlgZIYdIaLWw + BWJ + DvMF + UTPQawYlCHTuxMv + gKCSv + KCNtsojoyBuxYfZ + EkzcpXpY + ZLKkVMgNc + lsotzMOMFSOvCMI" fullword ascii
    $s4 = "i + lHqbRedsdcG + PnqMVkfqiIM + fyhQugXLUDs + CKKwRwcjwoaDbcK + bsjawJeEKjhr, false);" fullword ascii
    $s5 = "function tPqYQhCHXqN(n)" fullword ascii
    $s6 = "function otDLZQwZ(fname)" fullword ascii
    $s7 = "var qTygYgnIzsh = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}