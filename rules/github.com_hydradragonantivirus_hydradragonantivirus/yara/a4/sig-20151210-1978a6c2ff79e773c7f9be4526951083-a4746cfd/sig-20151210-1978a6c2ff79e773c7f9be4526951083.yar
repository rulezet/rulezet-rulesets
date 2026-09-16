rule sig_20151210_1978a6c2ff79e773c7f9be4526951083 {
  meta:
    description = "datamaliciousorder - file 20151210_1978a6c2ff79e773c7f9be4526951083.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec5755be274014b02d1f137366f9182bc82f4a3ce3c1f22b7ef83ec403f79816"

  strings:
    $s1  = "function tfKMpMt(TarIwUWUXZReWErOOJUGYPPSyIqsKNEebOwm) {return !isNaN(parseFloat(TarIwUWUXZReWErOOJUGYPPSyIqsKNEebOwm)) && isFin" ascii
    $s2  = "function tfKMpMt(TarIwUWUXZReWErOOJUGYPPSyIqsKNEebOwm) {return !isNaN(parseFloat(TarIwUWUXZReWErOOJUGYPPSyIqsKNEebOwm)) && isFin" ascii
    $s3  = "xdOOXxm=(-218+218)/389;while(true){if(xdOOXxm>=(116044+564)/911){break;}NjINkiDqSYGXq[xdOOXxm]=String.fromCharCode(xdOOXxm);xdOO" ascii
    $s4  = "RlGAKghM[qYWvedEtyob]=(-799+799)/180; while(true) { if(wRlGAKghM[qYWvedEtyob] > TYlGo[qYWvedEtyob].length-(202+155)/357) { break" ascii
    $s5  = ";}} return rDGelnkkjML}" fullword ascii
    $s6  = "function nSqNeHnHdubRIzRqL(TYlGo){rDGelnkkjML= '';for(qYWvedEtyob=(-673+673)/955; qYWvedEtyob < (374+780)/577; qYWvedEtyob++) {w" ascii
    $s7  = "function DLhvLoKloAjDzgZnLfDxfNQqOlbAtVwdXmbBdfGGVlKHxyJNZHQdBL(QtyNUsemEgDMh,MybhNGocBaobvQ){ return NjINkiDqSYGXq[neXFY(QtyNUs" ascii
    $s8  = "function neXFY(HtkHqnCVrWQ,FByDePACQbdgy,hjavJpam){flxd=parseInt(HtkHqnCVrWQ,FByDePACQbdgy);SKFJJ=flxd.toString(hjavJpam);return" ascii
    $s9  = "function DLhvLoKloAjDzgZnLfDxfNQqOlbAtVwdXmbBdfGGVlKHxyJNZHQdBL(QtyNUsemEgDMh,MybhNGocBaobvQ){ return NjINkiDqSYGXq[neXFY(QtyNUs" ascii
    $s10 = "xdOOXxm=(-218+218)/389;while(true){if(xdOOXxm>=(116044+564)/911){break;}NjINkiDqSYGXq[xdOOXxm]=String.fromCharCode(xdOOXxm);xdOO" ascii
    $s11 = "function bVYarawleob(WuoXuwnL,sCKCFl){return WuoXuwnL.split(sCKCFl)}" fullword ascii
    $s12 = "function nSqNeHnHdubRIzRqL(TYlGo){rDGelnkkjML= '';for(qYWvedEtyob=(-673+673)/955; qYWvedEtyob < (374+780)/577; qYWvedEtyob++) {w" ascii
    $s13 = " SKFJJ;}function WWwxmNjfAEtQEbM(ZlBDWWkjLiVoDQTHG){eval(ZlBDWWkjLiVoDQTHG)}" fullword ascii
    $s14 = "function neXFY(HtkHqnCVrWQ,FByDePACQbdgy,hjavJpam){flxd=parseInt(HtkHqnCVrWQ,FByDePACQbdgy);SKFJJ=flxd.toString(hjavJpam);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}