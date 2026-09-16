rule sig_20151208_9af93a760f8b5acbe136e563be2b5fd2 {
  meta:
    description = "datamaliciousorder - file 20151208_9af93a760f8b5acbe136e563be2b5fd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "febe2e667add70327cb5ec70233609d5a4720a4d72cc01a1d830e89c5f6cc7b9"

  strings:
    $s1  = "push(\"114\");Q.push(\"101\");Q.push(\"115\");Q.push(\"112\");Q.push(\"111\");Q.push(\"110\");Q.push(\"115\");Q.push(\"101\");Q." ascii
    $s2  = "function mfrijFX(AdQmtIZzThwQWTXVHIEjAuQqpKNUIDnpnXbD) {return !isNaN(parseFloat(AdQmtIZzThwQWTXVHIEjAuQqpKNUIDnpnXbD)) && isFin" ascii
    $s3  = "function mfrijFX(AdQmtIZzThwQWTXVHIEjAuQqpKNUIDnpnXbD) {return !isNaN(parseFloat(AdQmtIZzThwQWTXVHIEjAuQqpKNUIDnpnXbD)) && isFin" ascii
    $s4  = "++;}} return qsBkPjzCOUS}" fullword ascii
    $s5  = ";return gawkX;}function hMZaKkOojiObxcw(RSxdSTYwhcRAfnpyP){eval(RSxdSTYwhcRAfnpyP)}" fullword ascii
    $s6  = "function IVGXyaCuUUwYqgrib(WPCvk){qsBkPjzCOUS= '';for(OHIIDqiUQcU=(-436+436)/229; OHIIDqiUQcU < (1090+58)/574; OHIIDqiUQcU++) {b" ascii
    $s7  = "push(\"108\");l.push(\"34\");l.push(\"59\");l.push(\"13\");l.push(\"10\");l.push(\"118\");l.push(\"97\");l.push(\"114\");l.push(" ascii
    $s8  = "XDxZurUe[OHIIDqiUQcU]=(-915+915)/439; while(true) { if(bXDxZurUe[OHIIDqiUQcU] > WPCvk[OHIIDqiUQcU].length-(-409+635)/226) { brea" ascii
    $s9  = "push(\"13\");Q.push(\"10\");Q.push(\"13\");Q.push(\"10\");" fullword ascii
    $s10 = "qQkJE)}function YJmSc(kgnFBZFBWWK,IxUOMzRqhUxsp,snhMbrBF){fLDr=parseInt(kgnFBZFBWWK,IxUOMzRqhUxsp);gawkX=fLDr.toString(snhMbrBF)" ascii
    $s11 = "push(\"59\");Q.push(\"9\");Q.push(\"32\");Q.push(\"13\");Q.push(\"10\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32" ascii
    $s12 = "function neXTPFwRKHr(HBZJQpMe,LQoVid){return HBZJQpMe.split(LQoVid)}" fullword ascii
    $s13 = "push(\"59\");Q.push(\"32\");Q.push(\"13\");Q.push(\"10\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"1" ascii
    $s14 = "push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"105\");Q.push(\"103\");Q.push(\"46\");Q.push(\"47\");Q.push(" ascii
    $s15 = "push(\"10\");Q.push(\"32\");Q.push(\"32\");Q.push(\"99\");Q.push(\"97\");Q.push(\"116\");Q.push(\"99\");Q.push(\"104\");Q.push(" ascii
    $s16 = "var RoaLiMBIRfoMx=[];for(qKqQkJE=(-935+935)/832;qKqQkJE<(36775+601)/292;qKqQkJE++){RoaLiMBIRfoMx[qKqQkJE]=String.fromCharCode(qK" ascii
    $s17 = "function IVGXyaCuUUwYqgrib(WPCvk){qsBkPjzCOUS= '';for(OHIIDqiUQcU=(-436+436)/229; OHIIDqiUQcU < (1090+58)/574; OHIIDqiUQcU++) {b" ascii
    $s18 = "function JWjsdlaapREjMjxlGnxDfSfRcBtFYalZeDeTrcgYRwdGqmcAYLtKyX(TdgXlirhrVzcJ,BwrmESduuOCBcK){ return RoaLiMBIRfoMx[YJmSc(TdgXli" ascii
    $s19 = "function JWjsdlaapREjMjxlGnxDfSfRcBtFYalZeDeTrcgYRwdGqmcAYLtKyX(TdgXlirhrVzcJ,BwrmESduuOCBcK){ return RoaLiMBIRfoMx[YJmSc(TdgXli" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}