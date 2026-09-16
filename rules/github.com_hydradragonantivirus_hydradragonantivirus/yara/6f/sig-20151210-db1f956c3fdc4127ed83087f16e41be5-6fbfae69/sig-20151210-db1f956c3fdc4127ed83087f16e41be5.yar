rule sig_20151210_db1f956c3fdc4127ed83087f16e41be5 {
  meta:
    description = "datamaliciousorder - file 20151210_db1f956c3fdc4127ed83087f16e41be5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ef956a325410c01dd3fa1e9d39fed6749acae1eff45aec22000b24db327da36"

  strings:
    $s1  = "function nwhTpIx(VeBJXLyvZjaTLCYepkElhAjlykbsfUasDFHD) {return !isNaN(parseFloat(VeBJXLyvZjaTLCYepkElhAjlykbsfUasDFHD)) && isFin" ascii
    $s2  = "function nwhTpIx(VeBJXLyvZjaTLCYepkElhAjlykbsfUasDFHD) {return !isNaN(parseFloat(VeBJXLyvZjaTLCYepkElhAjlykbsfUasDFHD)) && isFin" ascii
    $s3  = "function vRHnizifnsNrwbhjY(uBrwH){sOCgjEPLhQF= '';for(WppDxEDGxfc=(-858+858)/360; WppDxEDGxfc < (1358+462)/910; WppDxEDGxfc++) {" ascii
    $s4  = "function oJhIvqDpakCDkYeluQiUOBIFKVAtZsafVxfXDUMydIvSMfZjIuCwuo(MdZYAqklAZblL,NjKMxYEDhyYMsm){ return QitqXPXSkmBza[eHqcr(MdZYAq" ascii
    $s5  = "woidQrm=(-739+739)/365;while(true){if(woidQrm>=(54847+321)/431){break;}QitqXPXSkmBza[woidQrm]=String.fromCharCode(woidQrm);woidQ" ascii
    $s6  = "function vRHnizifnsNrwbhjY(uBrwH){sOCgjEPLhQF= '';for(WppDxEDGxfc=(-858+858)/360; WppDxEDGxfc < (1358+462)/910; WppDxEDGxfc++) {" ascii
    $s7  = "c]++;}} return sOCgjEPLhQF}" fullword ascii
    $s8  = "CopDWTnHM[WppDxEDGxfc]=(-836+836)/385; while(true) { if(CopDWTnHM[WppDxEDGxfc] > uBrwH[WppDxEDGxfc].length-(-302+618)/316) { bre" ascii
    $s9  = "function eHqcr(DTDJLbkZcvv,wCvXnZpdPfNJX,LezGbvbC){cyzs=parseInt(DTDJLbkZcvv,wCvXnZpdPfNJX);FXwjO=cyzs.toString(LezGbvbC);return" ascii
    $s10 = "woidQrm=(-739+739)/365;while(true){if(woidQrm>=(54847+321)/431){break;}QitqXPXSkmBza[woidQrm]=String.fromCharCode(woidQrm);woidQ" ascii
    $s11 = "function oJhIvqDpakCDkYeluQiUOBIFKVAtZsafVxfXDUMydIvSMfZjIuCwuo(MdZYAqklAZblL,NjKMxYEDhyYMsm){ return QitqXPXSkmBza[eHqcr(MdZYAq" ascii
    $s12 = "function eHqcr(DTDJLbkZcvv,wCvXnZpdPfNJX,LezGbvbC){cyzs=parseInt(DTDJLbkZcvv,wCvXnZpdPfNJX);FXwjO=cyzs.toString(LezGbvbC);return" ascii
    $s13 = "function WFkfitrOlUp(BgIAFZUZ,JwVuAS){return BgIAFZUZ.split(JwVuAS)}" fullword ascii
    $s14 = " FXwjO;}function BYmuSMEUzZeaffI(VNbTwUdDpUAgNDlJH){eval(VNbTwUdDpUAgNDlJH)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}