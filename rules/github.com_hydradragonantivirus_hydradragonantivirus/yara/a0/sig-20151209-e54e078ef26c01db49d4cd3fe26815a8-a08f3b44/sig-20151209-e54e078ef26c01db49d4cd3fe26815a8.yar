rule sig_20151209_e54e078ef26c01db49d4cd3fe26815a8 {
  meta:
    description = "datamaliciousorder - file 20151209_e54e078ef26c01db49d4cd3fe26815a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5dcd74a246c85b4cd4c180f9cdc3bf35481177fcf93bdbdd3b0a38b104af383"

  strings:
    $s1  = "function xGauwCr(TQRZqIWwJKrAtJKTiodZepSpqUuAoLyQFfsB) {return !isNaN(parseFloat(TQRZqIWwJKrAtJKTiodZepSpqUuAoLyQFfsB)) && isFin" ascii
    $s2  = "function xGauwCr(TQRZqIWwJKrAtJKTiodZepSpqUuAoLyQFfsB) {return !isNaN(parseFloat(TQRZqIWwJKrAtJKTiodZepSpqUuAoLyQFfsB)) && isFin" ascii
    $s3  = "push(\"32\");H.push(\"13\");H.push(\"10\");H.push(\"32\");H.push(\"32\");H.push(\"32\");H.push(\"32\");H.push(\"125\");H.push(\"" ascii
    $s4  = "push(\"32\");t.push(\"57\");t.push(\"56\");t.push(\"48\");t.push(\"53\");t.push(\"50\");t.push(\"57\");t.push(\"59\");t.push(\"1" ascii
    $s5  = "push(\"116\");H.push(\"101\");H.push(\"40\");H.push(\"41\");H.push(\"41\");H.push(\"62\");H.push(\"48\");H.push(\"44\");H.push(" ascii
    $s6  = "KwBeu)}function sQtvo(HYHUAXBbQRW,JRWMOYbLeRjLV,NXDGNDVB){lFSv=parseInt(HYHUAXBbQRW,JRWMOYbLeRjLV);zYGBC=lFSv.toString(NXDGNDVB)" ascii
    $s7  = "function vrtRqvLfzeGLdvdPC(zYSmK){gzxTANGYpfv= '';for(QCnkBUGbtDl=(-260+260)/906; QCnkBUGbtDl < (-891+923)/16; QCnkBUGbtDl++) {B" ascii
    $s8  = "function vRJfZSrVsODkSnaqekYaQfYnRXvGoefrZitJfiFnlTckLttrgHywsj(azigcOjKpQNVj,bgfSrnhWsNWGtz){ return TRLTrWcYyxqxe[sQtvo(azigcO" ascii
    $s9  = "++;}} return gzxTANGYpfv}" fullword ascii
    $s10 = ";return zYGBC;}function XFQCHoFCvEvfRiZ(kfZRjUfvmDHsBZQjG){eval(kfZRjUfvmDHsBZQjG)}" fullword ascii
    $s11 = "push(\"116\");t.push(\"46\");t.push(\"67\");t.push(\"114\");t.push(\"101\");t.push(\"97\");t.push(\"116\");t.push(\"101\");t.pus" ascii
    $s12 = "push(\"86\");t.push(\"110\");t.push(\"103\");t.push(\"32\");t.push(\"61\");t.push(\"32\");t.push(\"107\");t.push(\"104\");t.push" ascii
    $s13 = "CqSBVtFX[QCnkBUGbtDl]=(-455+455)/559; while(true) { if(BCqSBVtFX[QCnkBUGbtDl] > zYSmK[QCnkBUGbtDl].length-(-445+997)/552) { brea" ascii
    $s14 = "function vrtRqvLfzeGLdvdPC(zYSmK){gzxTANGYpfv= '';for(QCnkBUGbtDl=(-260+260)/906; QCnkBUGbtDl < (-891+923)/16; QCnkBUGbtDl++) {B" ascii
    $s15 = "function qzfJPvCqQSg(SaqJWJAh,hgbJdS){return SaqJWJAh.split(hgbJdS)}" fullword ascii
    $s16 = "function vRJfZSrVsODkSnaqekYaQfYnRXvGoefrZitJfiFnlTckLttrgHywsj(azigcOjKpQNVj,bgfSrnhWsNWGtz){ return TRLTrWcYyxqxe[sQtvo(azigcO" ascii
    $s17 = "push(\"105\");H.push(\"84\");H.push(\"54\");H.push(\"53\");H.push(\"55\");H.push(\"77\");H.push(\"105\");H.push(\"52\");H.push(" ascii
    $s18 = "push(\"32\");H.push(\"49\");H.push(\"41\");H.push(\"32\");H.push(\"32\");H.push(\"123\");H.push(\"13\");H.push(\"10\");H.push(\"" ascii
    $s19 = "push(\"32\");H.push(\"61\");H.push(\"32\");H.push(\"34\");H.push(\"71\");H.push(\"69\");H.push(\"84\");H.push(\"34\");H.push(\"5" ascii
    $s20 = "push(\"32\");H.push(\"32\");H.push(\"32\");H.push(\"99\");H.push(\"97\");H.push(\"116\");H.push(\"99\");H.push(\"104\");H.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}