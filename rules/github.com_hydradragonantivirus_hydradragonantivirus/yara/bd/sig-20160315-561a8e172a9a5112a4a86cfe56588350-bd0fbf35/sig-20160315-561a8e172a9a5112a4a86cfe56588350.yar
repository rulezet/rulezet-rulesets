rule sig_20160315_561a8e172a9a5112a4a86cfe56588350 {
  meta:
    description = "datamaliciousorder - file 20160315_561a8e172a9a5112a4a86cfe56588350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "242c7471c9da7a3cdf34c2856b9fdeb658817224fe31e875bdfd076a56a82e7a"

  strings:
    $s1 = "while (Jaxqkw.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function FQWLEaPa(wzqf){WshShell[MdiulAQqMDNivk](wzqf, 0, 0);}" fullword ascii
    $s3 = "function lVMmZrF(n){return uJbjSttaxw + yfIrnkLdyjNLye + CIOCfjJ + KKiV + zCvNNZyEZstQ + ZfiOeHiIRpIiMEP + sFv + fgIThvNbAvOuTVg" ascii
    $s4 = "mh + epnMcuL + ZSvsK + fQqBoXx + XacH + gjSMDJoqs + wpJPEjpgtvNAV + nhjNVeYihknx + WXwmqHA, false);" fullword ascii
    $s5 = "Jaxqkw[WZxUTxtOAVBH + GWnDWCgd + EtxoLiqGtrR + udBBQSIbtXYGyoi](hDqmyjuN + aEbNeQ, BpirUiA + EcshziuGCyO + mCzwfI + BkaRP + hHlH" ascii
    $s6 = "function lVMmZrF(n){return uJbjSttaxw + yfIrnkLdyjNLye + CIOCfjJ + KKiV + zCvNNZyEZstQ + ZfiOeHiIRpIiMEP + sFv + fgIThvNbAvOuTVg" ascii
    $s7 = "var NzLEVU = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}