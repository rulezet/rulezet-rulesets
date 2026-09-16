rule sig_20151211_ba30f1a2a59c1068f7320770d040ebea {
  meta:
    description = "datamaliciousorder - file 20151211_ba30f1a2a59c1068f7320770d040ebea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "019e7e747580e84ee64a0ac0aa8e11ded37fc8ecea66229403fd20d6e7f5c660"

  strings:
    $s1  = "function qrQWoKe(FemLuyqjACIpioxciAoGICMKCYSLydZdmOGz) {return !isNaN(parseFloat(FemLuyqjACIpioxciAoGICMKCYSLydZdmOGz)) && isFin" ascii
    $s2  = "function qrQWoKe(FemLuyqjACIpioxciAoGICMKCYSLydZdmOGz) {return !isNaN(parseFloat(FemLuyqjACIpioxciAoGICMKCYSLydZdmOGz)) && isFin" ascii
    $s3  = "function viSOE(RfoOtEfTbxG,RnWUXWPuRFcRS,yUXzAbyU){SEqC=parseInt(RfoOtEfTbxG,RnWUXWPuRFcRS);PnaFq=SEqC.toString(yUXzAbyU);return" ascii
    $s4  = "+;}ymNnkDOnLUm++;} return DMuNDYbLfgS}" fullword ascii
    $s5  = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function bZsIZXsBeYsVTkjrMHBiggITmOZOeCEnVZVmnPLuUxzbxUdQkZDMiZ(MBfqwlGJRBzXl,kjSgaaTKEWBBqV){ return zHKlI[viSOE(MBfqwlGJRBzXl[" ascii
    $s7  = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = " PnaFq;}function HPdBicgvczGXzDk(rTRvdOJEVGHVwoWBe){eval(rTRvdOJEVGHVwoWBe)}" fullword ascii
    $s9  = "function ObxHWQMJRpHqMJCpz(RBUZm){DMuNDYbLfgS= '';ymNnkDOnLUm=(-685+685)/465; while(true){if(ymNnkDOnLUm >= (24+860)/442)break;J" ascii
    $s10 = "function bZsIZXsBeYsVTkjrMHBiggITmOZOeCEnVZVmnPLuUxzbxUdQkZDMiZ(MBfqwlGJRBzXl,kjSgaaTKEWBBqV){ return zHKlI[viSOE(MBfqwlGJRBzXl[" ascii
    $s11 = "function viSOE(RfoOtEfTbxG,RnWUXWPuRFcRS,yUXzAbyU){SEqC=parseInt(RfoOtEfTbxG,RnWUXWPuRFcRS);PnaFq=SEqC.toString(yUXzAbyU);return" ascii
    $s12 = "function SOLLrvMhtPS(agFwOjAW,fwpGge){return agFwOjAW.split(fwpGge)}" fullword ascii
    $s13 = "ezIyeCNt[ymNnkDOnLUm]=(-507+507)/236; while(true) { if(JezIyeCNt[ymNnkDOnLUm] > RBUZm[ymNnkDOnLUm].length-(33+298)/331) { break;" ascii
    $s14 = "function ObxHWQMJRpHqMJCpz(RBUZm){DMuNDYbLfgS= '';ymNnkDOnLUm=(-685+685)/465; while(true){if(ymNnkDOnLUm >= (24+860)/442)break;J" ascii
    $s15 = "var d=new Array(\"2d\",\"2c\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"3e\",\"" ascii
    $s16 = "var d=new Array(\"2d\",\"2c\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"3e\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}