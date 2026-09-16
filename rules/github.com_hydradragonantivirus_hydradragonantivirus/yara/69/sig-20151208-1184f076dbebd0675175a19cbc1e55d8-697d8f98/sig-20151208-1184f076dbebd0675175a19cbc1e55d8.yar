rule sig_20151208_1184f076dbebd0675175a19cbc1e55d8 {
  meta:
    description = "datamaliciousorder - file 20151208_1184f076dbebd0675175a19cbc1e55d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35596d9c8de5032fd45ee7158e2f86d589261405293ee79b0803b956d7098b6e"

  strings:
    $s1  = "function hTxAuQD(miwcNzdVkipMamIeBxzzdgRqAjtQmfMnOVTC) {return !isNaN(parseFloat(miwcNzdVkipMamIeBxzzdgRqAjtQmfMnOVTC)) && isFin" ascii
    $s2  = "push(\"108\");U.push(\"117\");U.push(\"100\");U.push(\"101\");U.push(\"115\");U.push(\"47\");U.push(\"112\");U.push(\"111\");U.p" ascii
    $s3  = "function hTxAuQD(miwcNzdVkipMamIeBxzzdgRqAjtQmfMnOVTC) {return !isNaN(parseFloat(miwcNzdVkipMamIeBxzzdgRqAjtQmfMnOVTC)) && isFin" ascii
    $s4  = "push(\"53\");B.push(\"53\");B.push(\"53\");B.push(\"56\");B.push(\"97\");B.push(\"100\");B.push(\"103\");B.push(\"101\");B.push(" ascii
    $s5  = "push(\"32\");B.push(\"32\");B.push(\"118\");B.push(\"97\");B.push(\"114\");B.push(\"32\");B.push(\"101\");B.push(\"116\");B.push" ascii
    $s6  = "function pPQUTmvoLmD(iScnPUif,hbyuFl){return iScnPUif.split(hbyuFl)}" fullword ascii
    $s7  = "FoRrXPqrT[iEOgWcQuHms]=(-864+864)/914; while(true) { if(FoRrXPqrT[iEOgWcQuHms] > SJNUq[iEOgWcQuHms].length-(-218+290)/72) { brea" ascii
    $s8  = "function UpWdSKDhqOtPXDKpmsGIGONNmNmhVlIvQuIfDFpBUkvvpLgSqpDwOk(dcwjaGTavgEKm,TMEjrrTCqgtuLy){ return QmwSybYItUkWp[odkQb(dcwjaG" ascii
    $s9  = "push(\"102\");B.push(\"32\");B.push(\"40\");B.push(\"109\");B.push(\"99\");B.push(\"46\");B.push(\"115\");B.push(\"116\");B.push" ascii
    $s10 = "return VOKFo;}function CTJcJbzNejPXhLQ(UoDjTxoCiuyKiujFW){eval(UoDjTxoCiuyKiujFW)}" fullword ascii
    $s11 = "push(\"32\");B.push(\"43\");B.push(\"32\");B.push(\"34\");B.push(\"66\");B.push(\"46\");B.push(\"83\");B.push(\"116\");B.push(\"" ascii
    $s12 = "push(\"100\");U.push(\"100\");U.push(\"100\");U.push(\"32\");U.push(\"61\");U.push(\"32\");U.push(\"34\");U.push(\"50\");U.push(" ascii
    $s13 = "push(\"114\");U.push(\"105\");U.push(\"112\");U.push(\"116\");U.push(\"46\");U.push(\"67\");U.push(\"114\");U.push(\"101\");U.pu" ascii
    $s14 = "push(\"32\");B.push(\"32\");B.push(\"32\");B.push(\"32\");B.push(\"99\");B.push(\"97\");B.push(\"116\");B.push(\"99\");B.push(\"" ascii
    $s15 = "push(\"110\");U.push(\"118\");U.push(\"105\");U.push(\"114\");U.push(\"111\");U.push(\"110\");U.push(\"109\");U.push(\"101\");U." ascii
    $s16 = "push(\"97\");B.push(\"108\");B.push(\"115\");B.push(\"101\");B.push(\"41\");B.push(\"59\");B.push(\"32\");B.push(\"109\");B.push" ascii
    $s17 = "push(\"95\");U.push(\"112\");U.push(\"97\");U.push(\"103\");U.push(\"101\");U.push(\"115\");U.push(\"95\");U.push(\"115\");U.pus" ascii
    $s18 = "function dTZRDgkktPqbquyWa(SJNUq){RIeHoPBqgZW= '';for(iEOgWcQuHms=(-207+207)/472; iEOgWcQuHms < (-550+768)/109; iEOgWcQuHms++) {" ascii
    $s19 = "function UpWdSKDhqOtPXDKpmsGIGONNmNmhVlIvQuIfDFpBUkvvpLgSqpDwOk(dcwjaGTavgEKm,TMEjrrTCqgtuLy){ return QmwSybYItUkWp[odkQb(dcwjaG" ascii
    $s20 = "function dTZRDgkktPqbquyWa(SJNUq){RIeHoPBqgZW= '';for(iEOgWcQuHms=(-207+207)/472; iEOgWcQuHms < (-550+768)/109; iEOgWcQuHms++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}