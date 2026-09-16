rule sig_20151209_f9d8a0e8a20b2321e7340245bfaaa4ef {
  meta:
    description = "datamaliciousorder - file 20151209_f9d8a0e8a20b2321e7340245bfaaa4ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e66e9c9d1681950c9184bc79b94b7ce0241bedecafaceaf8b232fe61b69e1ecd"

  strings:
    $s1  = "function QPjvhIA(LPscLKjtmcWfjZUzMppLlWgtXzOERDUnvhro) {return !isNaN(parseFloat(LPscLKjtmcWfjZUzMppLlWgtXzOERDUnvhro)) && isFin" ascii
    $s2  = "function QPjvhIA(LPscLKjtmcWfjZUzMppLlWgtXzOERDUnvhro) {return !isNaN(parseFloat(LPscLKjtmcWfjZUzMppLlWgtXzOERDUnvhro)) && isFin" ascii
    $s3  = "function vmfhOxETsAeiZKuwu(nAZbo){hREHRKBsqRb= '';for(OyNgjOKMbZn=(-929+929)/279; OyNgjOKMbZn < (461+211)/336; OyNgjOKMbZn++) {v" ascii
    $s4  = "RbsAmnLM[OyNgjOKMbZn]=(-675+675)/782; while(true) { if(vRbsAmnLM[OyNgjOKMbZn] > nAZbo[OyNgjOKMbZn].length-(-570+853)/283) { brea" ascii
    $s5  = "function trSOJCexWQD(QoHxGTTu,QwMaXT){return QoHxGTTu.split(QwMaXT)}" fullword ascii
    $s6  = " MaLHA;}function TLNtqKySAsFPien(wWkDPGpqRZBkrxyzk){eval(wWkDPGpqRZBkrxyzk)}" fullword ascii
    $s7  = "function vmfhOxETsAeiZKuwu(nAZbo){hREHRKBsqRb= '';for(OyNgjOKMbZn=(-929+929)/279; OyNgjOKMbZn < (461+211)/336; OyNgjOKMbZn++) {v" ascii
    $s8  = "function lStDhSdspDvqZEheNxbMCFWaiGfSZrscRIKAxUmWMDLbbKYgnaduHf(qxQaFMmgPZJVQ,MyGbbrAfTUrEuq){ return VMGic[JYdOV(qxQaFMmgPZJVQ[" ascii
    $s9  = "function lStDhSdspDvqZEheNxbMCFWaiGfSZrscRIKAxUmWMDLbbKYgnaduHf(qxQaFMmgPZJVQ,MyGbbrAfTUrEuq){ return VMGic[JYdOV(qxQaFMmgPZJVQ[" ascii
    $s10 = "++;}} return hREHRKBsqRb}" fullword ascii
    $s11 = "function JYdOV(eQtmWEKPXpn,IXeIsyvNogbKX,iJdROBMK){dtAH=parseInt(eQtmWEKPXpn,IXeIsyvNogbKX);MaLHA=dtAH.toString(iJdROBMK);return" ascii
    $s12 = "function JYdOV(eQtmWEKPXpn,IXeIsyvNogbKX,iJdROBMK){dtAH=parseInt(eQtmWEKPXpn,IXeIsyvNogbKX);MaLHA=dtAH.toString(iJdROBMK);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}