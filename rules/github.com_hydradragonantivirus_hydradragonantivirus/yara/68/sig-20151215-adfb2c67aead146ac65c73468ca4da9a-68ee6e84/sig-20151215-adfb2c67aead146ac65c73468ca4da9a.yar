rule sig_20151215_adfb2c67aead146ac65c73468ca4da9a {
  meta:
    description = "datamaliciousorder - file 20151215_adfb2c67aead146ac65c73468ca4da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a86e88af476d00e8b93ddec12a49bb5855db93f17a0a1395500980a6a7cca65"

  strings:
    $s1  = "Math.pow(Math.cos(443), 2) - 1)); while(true) { if(NMNEPFkSE[lzLTmTpeQHs] > rDwPJ[lzLTmTpeQHs].length-(96+583)/679) { break; } i" ascii
    $s2  = "ow(Math.cos(362), 2) - 1)));} NMNEPFkSE[lzLTmTpeQHs]++;}} return BItUkNOefuk}" fullword ascii
    $s3  = "function xgnUXLRYpqWJFbZdv(rDwPJ){BItUkNOefuk= U[1756];for(lzLTmTpeQHs=Math.round((Math.pow(Math.sin(246), 2) + Math.pow(Math.co" ascii
    $s4  = "function xgnUXLRYpqWJFbZdv(rDwPJ){BItUkNOefuk= U[1756];for(lzLTmTpeQHs=Math.round((Math.pow(Math.sin(246), 2) + Math.pow(Math.co" ascii
    $s5  = "function w(pIwqCiMPQEUV,EFbgMeCZHETSDq){pIwqCiMPQEUV.push(EFbgMeCZHETSDq);}function w8(sXXzkFZDcXAyEVEt){if(breekKI(sXXzkFZDcXAy" ascii
    $s6  = "EVEt)) {return (String.fromCharCode(sXXzkFZDcXAyEVEt) + String.fromCharCode((67085+711)/997));}}" fullword ascii
    $s7  = "function w(pIwqCiMPQEUV,EFbgMeCZHETSDq){pIwqCiMPQEUV.push(EFbgMeCZHETSDq);}function w8(sXXzkFZDcXAyEVEt){if(breekKI(sXXzkFZDcXAy" ascii
    $s8  = "var U=new Array();" fullword ascii
    $s9  = "function MIkSAxIYEdMDIqj(SWajACpiloKrekVCd){eval(SWajACpiloKrekVCd)}" fullword ascii
    $s10 = " ECvWE;}function MIkSAxIYEdMDIqj(SWajACpiloKrekVCd,AZLKXuUXmcLUABSIqmXUDmViMHeGTSPJhT,pIbgTWhUkfevaZDtCeKeNDqhPTzasNlbkrm){eval(" ascii
    $s11 = "function lowbNXyKxHNnyTVhezDbMnWobpssRCjtoEFsNkBrwLyjdcQPJmsUFH(sfdtaUKyvJXlO,jZMVjMRoKgTiKx){ return JwCNQtm[peAhdOdS[PymUf(sfd" ascii
    $s12 = "function hcVSdqPKoMa(EvLZYfxg,VtBqHM){return EvLZYfxg.split(VtBqHM)}" fullword ascii
    $s13 = "function PymUf(IWvOkfYKMTV,BEmZaEAyeOsbL,hGIcKduD){dHMH=parseInt(IWvOkfYKMTV,BEmZaEAyeOsbL);ECvWE=dHMH.toString(hGIcKduD);return" ascii
    $s14 = "function PymUf(IWvOkfYKMTV,BEmZaEAyeOsbL,hGIcKduD){dHMH=parseInt(IWvOkfYKMTV,BEmZaEAyeOsbL);ECvWE=dHMH.toString(hGIcKduD);return" ascii
    $s15 = "function lowbNXyKxHNnyTVhezDbMnWobpssRCjtoEFsNkBrwLyjdcQPJmsUFH(sfdtaUKyvJXlO,jZMVjMRoKgTiKx){ return JwCNQtm[peAhdOdS[PymUf(sfd" ascii
    $s16 = "function breekKI(whFqcIzmfQIoOwzNxVNzkSXLkaCaToKGtqKb) {return !isNaN(parseFloat(whFqcIzmfQIoOwzNxVNzkSXLkaCaToKGtqKb)) && isFin" ascii
    $s17 = "function breekKI(whFqcIzmfQIoOwzNxVNzkSXLkaCaToKGtqKb) {return !isNaN(parseFloat(whFqcIzmfQIoOwzNxVNzkSXLkaCaToKGtqKb)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}