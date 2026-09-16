rule sig_20151204_6052f29c97abf976f907d73c083642a2 {
  meta:
    description = "datamaliciousorder - file 20151204_6052f29c97abf976f907d73c083642a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ed0040cfd6c6e3b65bb6ee0a1de4a24ae36a3a0b54d99c3d72c59253652198"

  strings:
    $s1 = "function kdZMPVl(BrwkTImegFhIjbiNpoTfrqNMZKaZaWsUFoMv) {return !isNaN(parseFloat(BrwkTImegFhIjbiNpoTfrqNMZKaZaWsUFoMv)) && isFin" ascii
    $s2 = "function kdZMPVl(BrwkTImegFhIjbiNpoTfrqNMZKaZaWsUFoMv) {return !isNaN(parseFloat(BrwkTImegFhIjbiNpoTfrqNMZKaZaWsUFoMv)) && isFin" ascii
    $s3 = "function mqKcmZHGhSL(UlfmOFPh,QLYDqu){return UlfmOFPh.split(QLYDqu)}" fullword ascii
    $s4 = "function nIRuPptOnKqDXYt(obvvXeNOGeXRYeSQk){eval(obvvXeNOGeXRYeSQk)}" fullword ascii
    $s5 = "function BHwQBBvQScjZxcWVcOWJzTuTIVnRTpDkEaXwidUqwjjxWfXCVoWtAu(JszCBtYkTRopq,vqSxmYiJUXgGTk){ return String.fromCharCode(JszCBt" ascii
    $s6 = "Au([LnKRHXSplFcQ[VGZUMWMpwXrQxEYzEojUzFWFV]], 0);}} return MvEcVsdivJU}" fullword ascii
    $s7 = "function VHCCTszIFsyJswDfQ(cHHEbdDiqoyGto) { LnKRHXSplFcQ = mqKcmZHGhSL(cHHEbdDiqoyGto,'" fullword ascii
    $s8 = "'); MvEcVsdivJU= ''; for(VGZUMWMpwXrQxEYzEojUzFWFV=0; VGZUMWMpwXrQxEYzEojUzFWFV < LnKRHXSplFcQ.length; VGZUMWMpwXrQxEYzEojUzFWFV" ascii
    $s9 = "function BHwQBBvQScjZxcWVcOWJzTuTIVnRTpDkEaXwidUqwjjxWfXCVoWtAu(JszCBtYkTRopq,vqSxmYiJUXgGTk){ return String.fromCharCode(JszCBt" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}