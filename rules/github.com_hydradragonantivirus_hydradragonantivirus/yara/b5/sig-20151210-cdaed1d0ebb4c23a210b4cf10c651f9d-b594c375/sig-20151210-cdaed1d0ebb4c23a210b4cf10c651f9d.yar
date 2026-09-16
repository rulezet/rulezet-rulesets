rule sig_20151210_cdaed1d0ebb4c23a210b4cf10c651f9d {
  meta:
    description = "datamaliciousorder - file 20151210_cdaed1d0ebb4c23a210b4cf10c651f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91df057e25ed4fd3f35637ad7822dc50908fd77b0d0143e661f2dc490ebe8be"

  strings:
    $s1  = "function ZJgHRlT(KWjbqntXjPjIGVXtYkqsrhUrQEdGLtgCSBRc) {return !isNaN(parseFloat(KWjbqntXjPjIGVXtYkqsrhUrQEdGLtgCSBRc)) && isFin" ascii
    $s2  = "function ZJgHRlT(KWjbqntXjPjIGVXtYkqsrhUrQEdGLtgCSBRc) {return !isNaN(parseFloat(KWjbqntXjPjIGVXtYkqsrhUrQEdGLtgCSBRc)) && isFin" ascii
    $s3  = "function XHHYCCidcwOqVEPRBssqocNeAmJXgypDIMlzKtulKDKRBkfRzxDCgw(NASdokHsDlfxh,swsxKbQSEqHBZB){ return juLgWoRXsGysK[HojUe(NASdok" ascii
    $s4  = " peIoH;}function bplKWHETdIbatsb(ysBunxnyNqcRfpLxX){eval(ysBunxnyNqcRfpLxX)}" fullword ascii
    $s5  = " return ZCTjaBRFLgi}" fullword ascii
    $s6  = "function eKNQVNojtEjCIQJHE(xVZCp){ZCTjaBRFLgi= '';for(dXoHJiVqDLz=(-179+179)/66; dXoHJiVqDLz < (1524+168)/846; dXoHJiVqDLz++) {g" ascii
    $s7  = "QBpiHPT=(-954+954)/365;while(true){if(QBpiHPT>=(21843+45)/171){break;}juLgWoRXsGysK[QBpiHPT]=String.fromCharCode(QBpiHPT);QBpiHP" ascii
    $s8  = "function HojUe(eWapMxGvpdl,rZgUMjWnxUFIA,OaVKMsWG){ifiF=parseInt(eWapMxGvpdl,rZgUMjWnxUFIA);peIoH=ifiF.toString(OaVKMsWG);return" ascii
    $s9  = "function XHHYCCidcwOqVEPRBssqocNeAmJXgypDIMlzKtulKDKRBkfRzxDCgw(NASdokHsDlfxh,swsxKbQSEqHBZB){ return juLgWoRXsGysK[HojUe(NASdok" ascii
    $s10 = "NywRLAsB[dXoHJiVqDLz]=(-716+716)/704; while(true) { if(gNywRLAsB[dXoHJiVqDLz] > xVZCp[dXoHJiVqDLz].length-(32+24)/56) { break; }" ascii
    $s11 = "function WPqZBjOApPW(kTSmBLPe,vuQZnp){return kTSmBLPe.split(vuQZnp)}" fullword ascii
    $s12 = "function eKNQVNojtEjCIQJHE(xVZCp){ZCTjaBRFLgi= '';for(dXoHJiVqDLz=(-179+179)/66; dXoHJiVqDLz < (1524+168)/846; dXoHJiVqDLz++) {g" ascii
    $s13 = "QBpiHPT=(-954+954)/365;while(true){if(QBpiHPT>=(21843+45)/171){break;}juLgWoRXsGysK[QBpiHPT]=String.fromCharCode(QBpiHPT);QBpiHP" ascii
    $s14 = "function HojUe(eWapMxGvpdl,rZgUMjWnxUFIA,OaVKMsWG){ifiF=parseInt(eWapMxGvpdl,rZgUMjWnxUFIA);peIoH=ifiF.toString(OaVKMsWG);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}