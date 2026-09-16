rule sig_20151210_e1be5cf84d1a5a70752d8d45d6ebc6bc {
  meta:
    description = "datamaliciousorder - file 20151210_e1be5cf84d1a5a70752d8d45d6ebc6bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f240e61884921b205db66dce61ef41a6cb6aab177779ff024261688fa1ecf7b"

  strings:
    $s1  = " AdMFM;}function FYEqhORLhpkEaGv(enowNvJCfSpyKTaYB){eval(enowNvJCfSpyKTaYB)}" fullword ascii
    $s2  = "function OQnEH(aAPtUhWKluS,pERbHnWWWQQbK,WvSDVWsS){mqUy=parseInt(aAPtUhWKluS,pERbHnWWWQQbK);AdMFM=mqUy.toString(WvSDVWsS);return" ascii
    $s3  = "function pTYZjMF(mXwOcYIlaoDPokCfhcVkTZVPSIiyhEZJKYUr) {return !isNaN(parseFloat(mXwOcYIlaoDPokCfhcVkTZVPSIiyhEZJKYUr)) && isFin" ascii
    $s4  = "function pTYZjMF(mXwOcYIlaoDPokCfhcVkTZVPSIiyhEZJKYUr) {return !isNaN(parseFloat(mXwOcYIlaoDPokCfhcVkTZVPSIiyhEZJKYUr)) && isFin" ascii
    $s5  = "function PSPydbkzSEM(mlONcKPT,hcAdib){return mlONcKPT.split(hcAdib)}" fullword ascii
    $s6  = "HKmsiDg=(-488+488)/97;while(true){if(HKmsiDg>=(123506+526)/969){break;}CxPAecoIqwjDM[HKmsiDg]=String.fromCharCode(HKmsiDg);HKmsi" ascii
    $s7  = "function UlCxHsSgcZoChIgrLrrxSgcvSphlbCrczVBNLQgtqTytQaSwpCBgcY(fSuEtDBFzdWEN,JPnDESUNnIWdWv){ return CxPAecoIqwjDM[OQnEH(fSuEtD" ascii
    $s8  = "function dbFghgsbuuejzgGYi(pPWIj){BnOvbhBDIzZ= '';for(vPjsPctszJd=(-708+708)/804; vPjsPctszJd < (292+24)/158; vPjsPctszJd++) {tF" ascii
    $s9  = ";}} return BnOvbhBDIzZ}" fullword ascii
    $s10 = "function UlCxHsSgcZoChIgrLrrxSgcvSphlbCrczVBNLQgtqTytQaSwpCBgcY(fSuEtDBFzdWEN,JPnDESUNnIWdWv){ return CxPAecoIqwjDM[OQnEH(fSuEtD" ascii
    $s11 = "function OQnEH(aAPtUhWKluS,pERbHnWWWQQbK,WvSDVWsS){mqUy=parseInt(aAPtUhWKluS,pERbHnWWWQQbK);AdMFM=mqUy.toString(WvSDVWsS);return" ascii
    $s12 = "Rzzrtwf[vPjsPctszJd]=(-454+454)/932; while(true) { if(tFRzzrtwf[vPjsPctszJd] > pPWIj[vPjsPctszJd].length-(-392+505)/113) { break" ascii
    $s13 = "HKmsiDg=(-488+488)/97;while(true){if(HKmsiDg>=(123506+526)/969){break;}CxPAecoIqwjDM[HKmsiDg]=String.fromCharCode(HKmsiDg);HKmsi" ascii
    $s14 = "function dbFghgsbuuejzgGYi(pPWIj){BnOvbhBDIzZ= '';for(vPjsPctszJd=(-708+708)/804; vPjsPctszJd < (292+24)/158; vPjsPctszJd++) {tF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}