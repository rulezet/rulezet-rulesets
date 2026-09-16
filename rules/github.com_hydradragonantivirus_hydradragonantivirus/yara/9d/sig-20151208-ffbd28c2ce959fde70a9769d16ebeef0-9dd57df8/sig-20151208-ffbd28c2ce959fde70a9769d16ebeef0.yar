rule sig_20151208_ffbd28c2ce959fde70a9769d16ebeef0 {
  meta:
    description = "datamaliciousorder - file 20151208_ffbd28c2ce959fde70a9769d16ebeef0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5bba30fcb2b39d72f99fec5d67ddc8be5156f9c57561c807ea9dc9acfa656e1"

  strings:
    $s1  = "function pGbKkWoLWODsaaMbcnXoZzfRrPWWVmiSbsxJeqzFVcoDtFxwKEYhoM(gjmiqvVGEZcMu,rBZPQsDSNdLVrR){ return SqKlOPXrXheVV[IhJCb(gjmiqv" ascii
    $s2  = "function NTXZCQaSTcHMzylpl(mmozH){ffiTfhrfjKC= '';for(NGYbgnkTJpD=(-807+807)/258; NGYbgnkTJpD < (631+725)/678; NGYbgnkTJpD++) {n" ascii
    $s3  = "function pGbKkWoLWODsaaMbcnXoZzfRrPWWVmiSbsxJeqzFVcoDtFxwKEYhoM(gjmiqvVGEZcMu,rBZPQsDSNdLVrR){ return SqKlOPXrXheVV[IhJCb(gjmiqv" ascii
    $s4  = "function SnyjfjU(lexiLfboobyKnVhwMQQPTorDQpDRiaClSRkT) {return !isNaN(parseFloat(lexiLfboobyKnVhwMQQPTorDQpDRiaClSRkT)) && isFin" ascii
    $s5  = "function SnyjfjU(lexiLfboobyKnVhwMQQPTorDQpDRiaClSRkT) {return !isNaN(parseFloat(lexiLfboobyKnVhwMQQPTorDQpDRiaClSRkT)) && isFin" ascii
    $s6  = "push(\"53\");F.push(\"53\");F.push(\"51\");F.push(\"52\");F.push(\"49\");F.push(\"56\");F.push(\"44\");F.push(\"32\");F.push(\"3" ascii
    $s7  = "push(\"10\");b.push(\"118\");b.push(\"97\");b.push(\"114\");b.push(\"32\");b.push(\"98\");b.push(\"77\");b.push(\"32\");b.push(" ascii
    $s8  = "grsZ)}function IhJCb(ItnhDGqjVeq,ShxworPlqzhvq,cvhEiBaT){nbZD=parseInt(ItnhDGqjVeq,ShxworPlqzhvq);tDEuq=nbZD.toString(cvhEiBaT);" ascii
    $s9  = "push(\"34\");b.push(\"41\");b.push(\"43\");b.push(\"34\");b.push(\"112\");b.push(\"116\");b.push(\"46\");b.push(\"83\");b.push(" ascii
    $s10 = "push(\"45\");b.push(\"105\");b.push(\"110\");b.push(\"99\");b.push(\"108\");b.push(\"117\");b.push(\"100\");b.push(\"101\");b.pu" ascii
    $s11 = "return tDEuq;}function trPRpEPWWbYHHzE(HszmfkXOaMhMTBliX){eval(HszmfkXOaMhMTBliX)}" fullword ascii
    $s12 = "push(\"32\");F.push(\"55\");F.push(\"51\");F.push(\"55\");F.push(\"50\");F.push(\"53\");F.push(\"56\");F.push(\"59\");F.push(\"1" ascii
    $s13 = "push(\"110\");F.push(\"32\");F.push(\"61\");F.push(\"32\");F.push(\"48\");F.push(\"59\");F.push(\"32\");F.push(\"99\");F.push(\"" ascii
    $s14 = "function NTXZCQaSTcHMzylpl(mmozH){ffiTfhrfjKC= '';for(NGYbgnkTJpD=(-807+807)/258; NGYbgnkTJpD < (631+725)/678; NGYbgnkTJpD++) {n" ascii
    $s15 = "function HsvzfLvvzKy(hdHFamNT,ydsMam){return hdHFamNT.split(ydsMam)}" fullword ascii
    $s16 = "push(\"108\");F.push(\"115\");F.push(\"101\");F.push(\"41\");F.push(\"59\");F.push(\"32\");F.push(\"85\");F.push(\"105\");F.push" ascii
    $s17 = "EiaRzHZn[NGYbgnkTJpD]=(-142+142)/583; while(true) { if(nEiaRzHZn[NGYbgnkTJpD] > mmozH[NGYbgnkTJpD].length-(-338+354)/16) { break" ascii
    $s18 = "var SqKlOPXrXheVV=[];for(bMDgrsZ=(-651+651)/26;bMDgrsZ<(28647+281)/226;bMDgrsZ++){SqKlOPXrXheVV[bMDgrsZ]=String.fromCharCode(bMD" ascii
    $s19 = "push(\"88\");F.push(\"55\");F.push(\"56\");F.push(\"51\");F.push(\"49\");F.push(\"67\");F.push(\"70\");F.push(\"42\");F.push(\"4" ascii
    $s20 = "push(\"48\");F.push(\"59\");F.push(\"13\");F.push(\"10\");F.push(\"118\");F.push(\"97\");F.push(\"114\");F.push(\"32\");F.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}