rule sig_20160526_53ded1d0b895ea1ca5a5f301ef5650ec {
  meta:
    description = "datamaliciousorder - file 20160526_53ded1d0b895ea1ca5a5f301ef5650ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "228e3ff0d0739a8bb7ec5bd74d44b167886c211bd3e6bcad2b16dd295ad746f6"

  strings:
    $s1  = "round((Math.pow(Math.sin(582), 2) + Math.pow(Math.cos(582), 2) - 1))-390)) FRviSAGQcLyV += Yp(FVTHOzwKbNpu);else if (LJoMkbckATr" ascii
    $s2  = "function PQFGTlohAyd(xxMlZvfrAjnSH) {var rPDHdKepjxb = TxdOEUdAIbWUkGQfex.join(UPrVakRbYsRylRy[0]);var FVTHOzwKbNpu, mkvPyqT, VT" ascii
    $s3  = "2) + Math.pow(Math.cos(112), 2) - 1))-912) | cDrhEXwhzEaASPkqRWc<< (333 + Math.round((Math.pow(Math.sin(370), 2) + Math.pow(Math" ascii
    $s4  = "+ Math.pow(Math.cos(764), 2) - 1))-945) & 0xff;VTYIikmhqKMA = aSGCgfxAuftyNaHXMMK & 0xff;if (cDrhEXwhzEaASPkqRWc == (454 + Math." ascii
    $s5  = "function ARZhhkEOzbpKm(LkYftqXmGXjRXOaMHTqYpEt,RPpwxtst){return LkYftqXmGXjRXOaMHTqYpEt.charAt(RPpwxtst);}" fullword ascii
    $s6  = "function PQFGTlohAyd(xxMlZvfrAjnSH) {var rPDHdKepjxb = TxdOEUdAIbWUkGQfex.join(UPrVakRbYsRylRy[0]);var FVTHOzwKbNpu, mkvPyqT, VT" ascii
    $s7  = "wKbNpu, mkvPyqT);else FRviSAGQcLyV += HBAOsOq(FVTHOzwKbNpu, mkvPyqT, VTYIikmhqKMA);} while (VUuAC < xxMlZvfrAjnSH.length);return" ascii
    $s8  = "function HBAOsOq(ArjdHPWxnXP,tGiWzLzcKzdqukaJYKypQj,YnqCKJJucfTYM){return String.fromCharCode(ArjdHPWxnXP,tGiWzLzcKzdqukaJYKypQj" ascii
    $s9  = "function hjhLN(WclFvueOaQQY,VEHQZvJYgdmiEytUZVsgk){return WclFvueOaQQY.indexOf(VEHQZvJYgdmiEytUZVsgk);}" fullword ascii
    $s10 = "function lXsRN(aPpRVohyVYACZlNAR,OcoATpIuLXFO){return String.fromCharCode(aPpRVohyVYACZlNAR,OcoATpIuLXFO);}" fullword ascii
    $s11 = "function Yp(lsPDxNtOipERqYBolRb){return String.fromCharCode(lsPDxNtOipERqYBolRb);}" fullword ascii
    $s12 = "function HBAOsOq(ArjdHPWxnXP,tGiWzLzcKzdqukaJYKypQj,YnqCKJJucfTYM){return String.fromCharCode(ArjdHPWxnXP,tGiWzLzcKzdqukaJYKypQj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}