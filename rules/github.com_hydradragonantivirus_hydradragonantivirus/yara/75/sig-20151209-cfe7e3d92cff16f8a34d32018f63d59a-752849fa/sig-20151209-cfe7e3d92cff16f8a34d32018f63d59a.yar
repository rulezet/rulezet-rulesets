rule sig_20151209_cfe7e3d92cff16f8a34d32018f63d59a {
  meta:
    description = "datamaliciousorder - file 20151209_cfe7e3d92cff16f8a34d32018f63d59a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f140872847eb3e3c2a3a2b5b39ead0cac46f247bbac33bb978200e232a1be969"

  strings:
    $s1  = "function ISjwlOX(tymrBriXjEGgEcMfBUHrwABtOXwVnAiIwpLz) {return !isNaN(parseFloat(tymrBriXjEGgEcMfBUHrwABtOXwVnAiIwpLz)) && isFin" ascii
    $s2  = "function ISjwlOX(tymrBriXjEGgEcMfBUHrwABtOXwVnAiIwpLz) {return !isNaN(parseFloat(tymrBriXjEGgEcMfBUHrwABtOXwVnAiIwpLz)) && isFin" ascii
    $s3  = "function nKFIKORfxVaRRPpxyIACHfCCYYMtxIAiLCXEuBfluNREUDavxJTMNK(zRURJGOAUnGEF,vAdnczPBofkWRJ){ return hjrOV[lESRJ(zRURJGOAUnGEF[" ascii
    $s4  = ";}} return AQDVeCEOdBl}" fullword ascii
    $s5  = "function lESRJ(GnYKSbCllXn,UhsYUQzyfgxTR,aAOKxKFC){Ngpe=parseInt(GnYKSbCllXn,UhsYUQzyfgxTR);GSRJi=Ngpe.toString(aAOKxKFC);return" ascii
    $s6  = "function nKFIKORfxVaRRPpxyIACHfCCYYMtxIAiLCXEuBfluNREUDavxJTMNK(zRURJGOAUnGEF,vAdnczPBofkWRJ){ return hjrOV[lESRJ(zRURJGOAUnGEF[" ascii
    $s7  = " GSRJi;}function NjIGItKRNTsxxjd(YvmSWczxTmLCoEVdF){eval(YvmSWczxTmLCoEVdF)}" fullword ascii
    $s8  = "function EtyawjCKjgF(PEqDfgdO,QywNcw){return PEqDfgdO.split(QywNcw)}" fullword ascii
    $s9  = "function lESRJ(GnYKSbCllXn,UhsYUQzyfgxTR,aAOKxKFC){Ngpe=parseInt(GnYKSbCllXn,UhsYUQzyfgxTR);GSRJi=Ngpe.toString(aAOKxKFC);return" ascii
    $s10 = "function JVEjWGEAIxDnpjUPq(DLjig){AQDVeCEOdBl= '';for(RUCzFKYBHzP=(-631+631)/254; RUCzFKYBHzP < (1741+85)/913; RUCzFKYBHzP++) {A" ascii
    $s11 = "function JVEjWGEAIxDnpjUPq(DLjig){AQDVeCEOdBl= '';for(RUCzFKYBHzP=(-631+631)/254; RUCzFKYBHzP < (1741+85)/913; RUCzFKYBHzP++) {A" ascii
    $s12 = "VKLeQoIj[RUCzFKYBHzP]=(-786+786)/416; while(true) { if(AVKLeQoIj[RUCzFKYBHzP] > DLjig[RUCzFKYBHzP].length-(-564+734)/170) { brea" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}