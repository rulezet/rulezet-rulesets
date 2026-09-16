rule sig_20151209_b8a7466a01a8d2c607435e10a5b23076 {
  meta:
    description = "datamaliciousorder - file 20151209_b8a7466a01a8d2c607435e10a5b23076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db80a8d774b287ea573994c223f2917f944bbc2d91ef8c7cf33def679a7f1fbf"

  strings:
    $s1  = "function qlbzjZE(KiHnkXuAEWjIxHYqUsCQjgQLwNwoOLpqwxjb) {return !isNaN(parseFloat(KiHnkXuAEWjIxHYqUsCQjgQLwNwoOLpqwxjb)) && isFin" ascii
    $s2  = "function qlbzjZE(KiHnkXuAEWjIxHYqUsCQjgQLwNwoOLpqwxjb) {return !isNaN(parseFloat(KiHnkXuAEWjIxHYqUsCQjgQLwNwoOLpqwxjb)) && isFin" ascii
    $s3  = "function ookmxjFLwpXbzbvSOhjFWNtMtVFTxEbjPXMARZnGReokmMvgPkYtuj(bKZNZBYbaBCIm,AMKvZjPjeGnIXI){ return SPprh[eadVJ(bKZNZBYbaBCIm[" ascii
    $s4  = "SPokD[FEVSSoXCoyZ]=(-73+73)/457; while(true) { if(MPDYSPokD[FEVSSoXCoyZ] > pWGNo[FEVSSoXCoyZ].length-(-6+542)/536) { break; } if" ascii
    $s5  = "function eadVJ(pqQlFWwBbQl,ywgAxiEyuSjQD,ZxUTunhx){XacS=parseInt(pqQlFWwBbQl,ywgAxiEyuSjQD);uqEgo=XacS.toString(ZxUTunhx);return" ascii
    $s6  = "function XihvsCVYePfVtdnTE(pWGNo){YyVSIueJhvD= '';for(FEVSSoXCoyZ=(-87+87)/789; FEVSSoXCoyZ < (887+65)/476; FEVSSoXCoyZ++) {MPDY" ascii
    $s7  = "function XihvsCVYePfVtdnTE(pWGNo){YyVSIueJhvD= '';for(FEVSSoXCoyZ=(-87+87)/789; FEVSSoXCoyZ < (887+65)/476; FEVSSoXCoyZ++) {MPDY" ascii
    $s8  = "function eadVJ(pqQlFWwBbQl,ywgAxiEyuSjQD,ZxUTunhx){XacS=parseInt(pqQlFWwBbQl,ywgAxiEyuSjQD);uqEgo=XacS.toString(ZxUTunhx);return" ascii
    $s9  = "function jeUCljkgwQx(icUlsdFP,RPKQhN){return icUlsdFP.split(RPKQhN)}" fullword ascii
    $s10 = " uqEgo;}function sjaVYwINazeziGo(vUDlmggxjNaYMWMRj){eval(vUDlmggxjNaYMWMRj)}" fullword ascii
    $s11 = "function ookmxjFLwpXbzbvSOhjFWNtMtVFTxEbjPXMARZnGReokmMvgPkYtuj(bKZNZBYbaBCIm,AMKvZjPjeGnIXI){ return SPprh[eadVJ(bKZNZBYbaBCIm[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}