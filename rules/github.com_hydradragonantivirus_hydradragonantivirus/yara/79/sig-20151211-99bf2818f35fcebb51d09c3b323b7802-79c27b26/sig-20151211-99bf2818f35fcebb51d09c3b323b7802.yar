rule sig_20151211_99bf2818f35fcebb51d09c3b323b7802 {
  meta:
    description = "datamaliciousorder - file 20151211_99bf2818f35fcebb51d09c3b323b7802.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d42b035974850fac719114eca5122817be192e6160bdbe8d250b4106fc3068e"

  strings:
    $s1  = "var L=new Array(\"2e\",\"2f\",\"2a\",\"28\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s2  = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s3  = "function TmZNScEXRqKDwyzpO(QYVHm){GqJzQKNJpJG= '';CJZfNKRBzVW=(-399+399)/681; while(true){if(CJZfNKRBzVW >= (411+305)/358)break;" ascii
    $s4  = "function gPmuRcSAEtceWPLNQUHIWwyOLoBbtzbfitXIjJylzXGtAgcwzAoOej(vQrtFjyDvRaio,NtJKZRAolMxZFt){ return JbRkX[HUhSS(vQrtFjyDvRaio[" ascii
    $s5  = "var L=new Array(\"2e\",\"2f\",\"2a\",\"28\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = " nAGuP;}function gJbMrFGJKazebyY(gynuqKSJDxvrGMzId){eval(gynuqKSJDxvrGMzId)}" fullword ascii
    $s7  = "function HFzzwJnckcY(PukgIDLv,EUmBfn){return PukgIDLv.split(EUmBfn)}" fullword ascii
    $s8  = "function TmZNScEXRqKDwyzpO(QYVHm){GqJzQKNJpJG= '';CJZfNKRBzVW=(-399+399)/681; while(true){if(CJZfNKRBzVW >= (411+305)/358)break;" ascii
    $s9  = "var J=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "function gPmuRcSAEtceWPLNQUHIWwyOLoBbtzbfitXIjJylzXGtAgcwzAoOej(vQrtFjyDvRaio,NtJKZRAolMxZFt){ return JbRkX[HUhSS(vQrtFjyDvRaio[" ascii
    $s11 = "function HUhSS(nbZjqeflSQI,xAKIMeRfGPrHa,wucCxUTv){kLBb=parseInt(nbZjqeflSQI,xAKIMeRfGPrHa);nAGuP=kLBb.toString(wucCxUTv);return" ascii
    $s12 = "function HUhSS(nbZjqeflSQI,xAKIMeRfGPrHa,wucCxUTv){kLBb=parseInt(nbZjqeflSQI,xAKIMeRfGPrHa);nAGuP=kLBb.toString(wucCxUTv);return" ascii
    $s13 = "+;}CJZfNKRBzVW++;} return GqJzQKNJpJG}" fullword ascii
    $s14 = "pSkFDIvKE[CJZfNKRBzVW]=(-326+326)/768; while(true) { if(pSkFDIvKE[CJZfNKRBzVW] > QYVHm[CJZfNKRBzVW].length-(578+348)/926) { brea" ascii
    $s15 = "function yDxUUVd(xtcmSiTUBRdfhwcAnqjAUVWhhnNLklPsIXrM) {return !isNaN(parseFloat(xtcmSiTUBRdfhwcAnqjAUVWhhnNLklPsIXrM)) && isFin" ascii
    $s16 = "function yDxUUVd(xtcmSiTUBRdfhwcAnqjAUVWhhnNLklPsIXrM) {return !isNaN(parseFloat(xtcmSiTUBRdfhwcAnqjAUVWhhnNLklPsIXrM)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}