rule sig_20151208_24a57541e1bacde1d200c9ac5ab818cb {
  meta:
    description = "datamaliciousorder - file 20151208_24a57541e1bacde1d200c9ac5ab818cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46b0e9edeb857ccc5db195b1f8f8913b8ea9f1c005a9349b36dd5181f22eb961"

  strings:
    $s1  = "function mbVNxIO(BOjAvtoGjPSxGGzQtCREGVpRcYlhOdrzzbIm) {return !isNaN(parseFloat(BOjAvtoGjPSxGGzQtCREGVpRcYlhOdrzzbIm)) && isFin" ascii
    $s2  = "function mbVNxIO(BOjAvtoGjPSxGGzQtCREGVpRcYlhOdrzzbIm) {return !isNaN(parseFloat(BOjAvtoGjPSxGGzQtCREGVpRcYlhOdrzzbIm)) && isFin" ascii
    $s3  = "push(\"32\");A.push(\"81\");A.push(\"106\");A.push(\"122\");A.push(\"46\");A.push(\"112\");A.push(\"111\");A.push(\"115\");A.pus" ascii
    $s4  = "return iihFX;}function UKSwqkZwfAcNUcE(DkkkPpNyUrEPbABEg){eval(DkkkPpNyUrEPbABEg)}" fullword ascii
    $s5  = "push(\"51\");P.push(\"57\");P.push(\"48\");P.push(\"55\");P.push(\"50\");P.push(\"117\");P.push(\"77\");P.push(\"51\");P.push(\"" ascii
    $s6  = "yiEc[gopemmelees]=(-291+291)/898; while(true) { if(XTBJhyiEc[gopemmelees] > CTNjD[gopemmelees].length-(163+453)/616) { break; } " ascii
    $s7  = "function PJUlpUWlhCvKsHQqe(CTNjD){vioVGGfbdHO= '';for(gopemmelees=(-2+2)/843; gopemmelees < (895+665)/780; gopemmelees++) {XTBJh" ascii
    $s8  = "push(\"116\");A.push(\"46\");A.push(\"67\");A.push(\"114\");A.push(\"101\");A.push(\"97\");A.push(\"116\");A.push(\"101\");A.pus" ascii
    $s9  = "var NqhwzwRoHalNC=[];for(svgHYVM=(-164+164)/33;svgHYVM<(82545+271)/647;svgHYVM++){NqhwzwRoHalNC[svgHYVM]=String.fromCharCode(svg" ascii
    $s10 = "push(\"32\");A.push(\"116\");A.push(\"114\");A.push(\"121\");A.push(\"32\");A.push(\"32\");A.push(\"123\");A.push(\"13\");A.push" ascii
    $s11 = "HYVM)}function zgGSc(LWGWkuopPMS,ubSnZmTecCiva,ZXhIyfnZ){xzLD=parseInt(LWGWkuopPMS,ubSnZmTecCiva);iihFX=xzLD.toString(ZXhIyfnZ);" ascii
    $s12 = "push(\"32\");A.push(\"43\");A.push(\"32\");A.push(\"34\");A.push(\"66\");A.push(\"46\");A.push(\"83\");A.push(\"116\");A.push(\"" ascii
    $s13 = "push(\"49\");P.push(\"55\");P.push(\"50\");P.push(\"53\");" fullword ascii
    $s14 = "function SXghsEsxWKJ(juoRIDUK,gYLKBg){return juoRIDUK.split(gYLKBg)}" fullword ascii
    $s15 = "push(\"45\");P.push(\"105\");P.push(\"110\");P.push(\"99\");P.push(\"108\");P.push(\"117\");P.push(\"100\");P.push(\"101\");P.pu" ascii
    $s16 = "push(\"97\");P.push(\"114\");P.push(\"32\");P.push(\"108\");P.push(\"109\");P.push(\"72\");P.push(\"32\");P.push(\"61\");P.push(" ascii
    $s17 = "function PJUlpUWlhCvKsHQqe(CTNjD){vioVGGfbdHO= '';for(gopemmelees=(-2+2)/843; gopemmelees < (895+665)/780; gopemmelees++) {XTBJh" ascii
    $s18 = "function fgjKHwTvMnpONMXAMaVmCaVXLJhDcRiwzoFlynOkIkiqtrzagkicZW(kXxIHNAjTyQMb,hxSbmdVbtwRnon){ return NqhwzwRoHalNC[zgGSc(kXxIHN" ascii
    $s19 = "function fgjKHwTvMnpONMXAMaVmCaVXLJhDcRiwzoFlynOkIkiqtrzagkicZW(kXxIHNAjTyQMb,hxSbmdVbtwRnon){ return NqhwzwRoHalNC[zgGSc(kXxIHN" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}