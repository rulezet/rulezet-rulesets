rule sig_20151208_bcd205c43d07baa67c7d8ede34d674fb {
  meta:
    description = "datamaliciousorder - file 20151208_bcd205c43d07baa67c7d8ede34d674fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d64eaacefeb03e8afe8daaeb98896afc342d846dae14c2fbaf547316b4577a"

  strings:
    $s1  = "function pkkxhCy(SlyJESZNcXWZIhxRFMKZgIzBOSAJfUkYXfEY) {return !isNaN(parseFloat(SlyJESZNcXWZIhxRFMKZgIzBOSAJfUkYXfEY)) && isFin" ascii
    $s2  = "function pkkxhCy(SlyJESZNcXWZIhxRFMKZgIzBOSAJfUkYXfEY) {return !isNaN(parseFloat(SlyJESZNcXWZIhxRFMKZgIzBOSAJfUkYXfEY)) && isFin" ascii
    $s3  = "push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"125\");e.push(\"59\");e.push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"" ascii
    $s4  = ";return iPvDO;}function IOzSvCsdRXuMtpT(oEokTLNQelpbFevEV){eval(oEokTLNQelpbFevEV)}" fullword ascii
    $s5  = "HRcKRjmx[taCplSRWaSp]=(-594+594)/549; while(true) { if(UHRcKRjmx[taCplSRWaSp] > trxsI[taCplSRWaSp].length-(-49+866)/817) { break" ascii
    $s6  = "iCCwW)}function fNkrW(eGQKraCDVwu,JcYgInvomldXB,yZBmDAJb){joOd=parseInt(eGQKraCDVwu,JcYgInvomldXB);iPvDO=joOd.toString(yZBmDAJb)" ascii
    $s7  = "push(\"114\");e.push(\"105\");e.push(\"122\");e.push(\"86\");e.push(\"68\");e.push(\"43\");e.push(\"34\");e.push(\"46\");e.push(" ascii
    $s8  = "push(\"34\");d.push(\"59\");d.push(\"13\");d.push(\"10\");d.push(\"118\");d.push(\"97\");d.push(\"114\");d.push(\"32\");d.push(" ascii
    $s9  = "push(\"61\");e.push(\"32\");e.push(\"48\");e.push(\"59\");e.push(\"13\");e.push(\"10\");e.push(\"32\");e.push(\"32\");e.push(\"1" ascii
    $s10 = "push(\"102\");e.push(\"75\");e.push(\"80\");e.push(\"46\");e.push(\"112\");e.push(\"111\");e.push(\"115\");e.push(\"105\");e.pus" ascii
    $s11 = "function xOnXrElKDVfdZIOpM(trxsI){laaLwrNRNrm= '';for(taCplSRWaSp=(-241+241)/389; taCplSRWaSp < (524+704)/614; taCplSRWaSp++) {U" ascii
    $s12 = "function sLlApzxUqdUfKPNhBojzmsBxFUHatpfuzDIBpHVCcqWPXwdGXIcdEo(RDFrnamUfWEwB,ypJZdbqxFItOht){ return FZHoNUQCoPYpZ[fNkrW(RDFrna" ascii
    $s13 = "push(\"80\");e.push(\"46\");e.push(\"115\");e.push(\"105\");e.push(\"122\");e.push(\"101\");e.push(\"32\");e.push(\"62\");e.push" ascii
    $s14 = "function xOnXrElKDVfdZIOpM(trxsI){laaLwrNRNrm= '';for(taCplSRWaSp=(-241+241)/389; taCplSRWaSp < (524+704)/614; taCplSRWaSp++) {U" ascii
    $s15 = "push(\"59\");d.push(\"13\");d.push(\"10\");d.push(\"118\");d.push(\"97\");d.push(\"114\");d.push(\"32\");d.push(\"114\");d.push(" ascii
    $s16 = "var FZHoNUQCoPYpZ=[];for(CXiCCwW=(-409+409)/542;CXiCCwW<(67056+528)/528;CXiCCwW++){FZHoNUQCoPYpZ[CXiCCwW]=String.fromCharCode(CX" ascii
    $s17 = "}} return laaLwrNRNrm}" fullword ascii
    $s18 = "push(\"52\");e.push(\"49\");e.push(\"52\");e.push(\"83\");e.push(\"108\");e.push(\"53\");e.push(\"42\");e.push(\"47\");e.push(\"" ascii
    $s19 = "function ldDDLAFVPdK(esTbdOxP,xEwrSH){return esTbdOxP.split(xEwrSH)}" fullword ascii
    $s20 = "function sLlApzxUqdUfKPNhBojzmsBxFUHatpfuzDIBpHVCcqWPXwdGXIcdEo(RDFrnamUfWEwB,ypJZdbqxFItOht){ return FZHoNUQCoPYpZ[fNkrW(RDFrna" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}