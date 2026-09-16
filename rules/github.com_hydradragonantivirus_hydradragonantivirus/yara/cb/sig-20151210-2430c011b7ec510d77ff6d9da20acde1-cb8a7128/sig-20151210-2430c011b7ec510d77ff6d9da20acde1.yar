rule sig_20151210_2430c011b7ec510d77ff6d9da20acde1 {
  meta:
    description = "datamaliciousorder - file 20151210_2430c011b7ec510d77ff6d9da20acde1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84c917127b2568a82cc19997e5526cea4b5cf049a85b8f4e412fabda117d5b16"

  strings:
    $s1  = "function oeXwWaC(ZZQbWVKWwJPAoSXDSQkVgPGiDMKAxBtWEGyR) {return !isNaN(parseFloat(ZZQbWVKWwJPAoSXDSQkVgPGiDMKAxBtWEGyR)) && isFin" ascii
    $s2  = "function oeXwWaC(ZZQbWVKWwJPAoSXDSQkVgPGiDMKAxBtWEGyR) {return !isNaN(parseFloat(ZZQbWVKWwJPAoSXDSQkVgPGiDMKAxBtWEGyR)) && isFin" ascii
    $s3  = "function DyZdPleruCTYpIxyH(rJrOa){YmSGZrnKUIE= '';for(cUEehsAlFgL=(-780+780)/307; cUEehsAlFgL < (1394+78)/736; cUEehsAlFgL++) {o" ascii
    $s4  = "BLyjxExi[cUEehsAlFgL]=(-116+116)/936; while(true) { if(oBLyjxExi[cUEehsAlFgL] > rJrOa[cUEehsAlFgL].length-(-218+843)/625) { brea" ascii
    $s5  = "function pFabc(gbAtEisOSvV,flzWsxyjmZrVi,yxyqMwKu){EHCk=parseInt(gbAtEisOSvV,flzWsxyjmZrVi);VAiGb=EHCk.toString(yxyqMwKu);return" ascii
    $s6  = "function usfnUkcRNrG(qiSkkcka,MYIqPv){return qiSkkcka.split(MYIqPv)}" fullword ascii
    $s7  = "xNcRNid=(-963+963)/733;while(true){if(xNcRNid>=(31403+981)/253){break;}DVJriBPVdYtzU[xNcRNid]=String.fromCharCode(xNcRNid);xNcRN" ascii
    $s8  = " VAiGb;}function uZrxdiLKCGDYCuh(bCPPlWNBxihlcYEJI){eval(bCPPlWNBxihlcYEJI)}" fullword ascii
    $s9  = "function DyZdPleruCTYpIxyH(rJrOa){YmSGZrnKUIE= '';for(cUEehsAlFgL=(-780+780)/307; cUEehsAlFgL < (1394+78)/736; cUEehsAlFgL++) {o" ascii
    $s10 = " return YmSGZrnKUIE}" fullword ascii
    $s11 = "function pFabc(gbAtEisOSvV,flzWsxyjmZrVi,yxyqMwKu){EHCk=parseInt(gbAtEisOSvV,flzWsxyjmZrVi);VAiGb=EHCk.toString(yxyqMwKu);return" ascii
    $s12 = "xNcRNid=(-963+963)/733;while(true){if(xNcRNid>=(31403+981)/253){break;}DVJriBPVdYtzU[xNcRNid]=String.fromCharCode(xNcRNid);xNcRN" ascii
    $s13 = "function sNiOdpvoImmjysBNbxTPcjqdZWydDgJRjCwgGjXedPrDndJJKJEDhB(hsbotPYouFFlj,BdcYacaEvRgKUI){ return DVJriBPVdYtzU[pFabc(hsbotP" ascii
    $s14 = "function sNiOdpvoImmjysBNbxTPcjqdZWydDgJRjCwgGjXedPrDndJJKJEDhB(hsbotPYouFFlj,BdcYacaEvRgKUI){ return DVJriBPVdYtzU[pFabc(hsbotP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}