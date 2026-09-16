rule sig_20160316_e4495bc4d420f70df80505fcfce5e8f4 {
  meta:
    description = "datamaliciousorder - file 20160316_e4495bc4d420f70df80505fcfce5e8f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ffb2d88b229e42643ae7161ba33b3805a12fe8df98807dbc9952a9c147a7b27"

  strings:
    $s1 = "while (yHcku[lsybbdNXWOVsAC + Nmfwsiu + HApeyCGJQ + gacAt] < 4 ) {WScript[PHI + SfIIytyMiosRzM + RpgfVMHmqiyj](1000)};" fullword ascii
    $s2 = "function BfwisXxRJcTfoZU(n){return Oyce + hcqLPTYCXZo + nWED + PRoQ + ljAFP + RdWrw;}" fullword ascii
    $s3 = "function AdQ0(rhMoauBXSTJgCmi){UhTb[CgqOVFoJ + zbGfxziOnPBVp](rhMoauBXSTJgCmi, 0, 0);}" fullword ascii
    $s4 = "Vghw + DAqsmsvTnPY, false);" fullword ascii
    $s5 = "var DKmHsyLkiFIzlLs = new Date();" fullword ascii
    $s6 = "yHcku[SuAAHl + YrQhxHGnJlbDw](LWj, dRTRN + rwugcUZONbPIHp + GFGzQVlhhhg + pMfhLD + sWNAxunCUrDsNEX + fDAqnsTRHf + yKaKdMtnaNZnwX" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}