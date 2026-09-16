rule sig_20160531_38c52529225c9d86fcc9987a91541e17 {
  meta:
    description = "datamaliciousorder - file 20160531_38c52529225c9d86fcc9987a91541e17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5f4bd9c9cc251a50221d8f259edaeabee0e7836b0ea89c7f9ae2f93b8f48842"

  strings:
    $s1  = "var RapyqRof=function(){return WScript.CreateObject(dnAggwxVQebyXXghaR[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function HOAQZYsJVfjc(uwcTwcHj,wsTGKIAHGgMoLtprY){return uwcTwcHj.charAt(wsTGKIAHGgMoLtprY);}" fullword ascii
    $s3  = "function DBNfnjwoOe(pTQHVCqNFqDvR,pRBqMeJJNFTrOAzM,IFmXuvs){return String.fromCharCode(pTQHVCqNFqDvR,pRBqMeJJNFTrOAzM,IFmXuvs);}" ascii
    $s4  = "function zCygNfibdyrhN(){return RapyqRof.ExpandEnvironmentStrings(uQxxHYZEaRra())}" fullword ascii
    $s5  = "function sjbBIhqOm(){return tsrYHjjKaef(dnAggwxVQebyXXghaR[11],[2,4,8,10],dnAggwxVQebyXXghaR[12]);}" fullword ascii
    $s6  = "function zYmvbsipba(){return tsrYHjjKaef(dnAggwxVQebyXXghaR[13],[0,3,6],dnAggwxVQebyXXghaR[14]);}" fullword ascii
    $s7  = "function Zy(LoiHvzGRq){return String.fromCharCode(LoiHvzGRq);}" fullword ascii
    $s8  = "function rWaEOTpHSSVDHKA(ArvTt,RwvhGCQiHMhzAhjSUKTqQ){return ArvTt.indexOf(RwvhGCQiHMhzAhjSUKTqQ);}" fullword ascii
    $s9  = "pMrkyjCJogQ);} while (sbaiAkHVWmXCzAqtrtAJyUQp < sSiZHstqJzUgP.length);return ofbvQtEXHEkNdIlhpwRXlwIf;}" fullword ascii
    $s10 = "function tsrYHjjKaef(GtYTTG,RixZnTN,BcsVELMFzYvFC){sIBArMByKHiXCI=GtYTTG.split(BcsVELMFzYvFC);oGhyGWKrfQBuhk = dnAggwxVQebyXXgha" ascii
    $s11 = "function XgOULLdGgMGniIQnmRSa(ftgEagaUmZOnTSVBwm,ojypdjeILILMGFZGtyfQBOej){return String.fromCharCode(ftgEagaUmZOnTSVBwm,ojypdje" ascii
    $s12 = "(tafbEEfunmDlg,0x1,0x0)}function qtENsCMvstlto(vmGopCK,QcOIjsfJK,zQvxz){var FfbmTwvyLUJC=vmGopCK.createtextfile(QcOIjsfJK,true);" ascii
    $s13 = "function elipxtrkadvH(sSiZHstqJzUgP) {var IFKwNZGBedtYEYuXb = fWJkVgdTQCw.join(dnAggwxVQebyXXghaR[7]);var CznOzRWfsmewCPQqPT, Gk" ascii
    $s14 = "WYKeEV == 64) ofbvQtEXHEkNdIlhpwRXlwIf += Zy(CznOzRWfsmewCPQqPT);else if (QXnZIg == 64) ofbvQtEXHEkNdIlhpwRXlwIf += XgOULLdGgMGn" ascii
    $s15 = "R[0];for(ORpnWIW=0;ORpnWIW<RixZnTN.length;ORpnWIW++) {oGhyGWKrfQBuhk+=sIBArMByKHiXCI[RixZnTN[ORpnWIW]];}return oGhyGWKrfQBuhk.su" ascii
    $s16 = "var SqtWckZbC=function(){return new ActiveXObject(dnAggwxVQebyXXghaR[1]);}();" fullword ascii
    $s17 = "function uQxxHYZEaRra(){return tsrYHjjKaef(dnAggwxVQebyXXghaR[9],[1,5,7],dnAggwxVQebyXXghaR[10]);}" fullword ascii
    $s18 = "function tsrYHjjKaef(GtYTTG,RixZnTN,BcsVELMFzYvFC){sIBArMByKHiXCI=GtYTTG.split(BcsVELMFzYvFC);oGhyGWKrfQBuhk = dnAggwxVQebyXXgha" ascii
    $s19 = "function elipxtrkadvH(sSiZHstqJzUgP) {var IFKwNZGBedtYEYuXb = fWJkVgdTQCw.join(dnAggwxVQebyXXghaR[7]);var CznOzRWfsmewCPQqPT, Gk" ascii
    $s20 = "iIQnmRSa(CznOzRWfsmewCPQqPT, GkvqHDKUhHbpklP);else ofbvQtEXHEkNdIlhpwRXlwIf += DBNfnjwoOe(CznOzRWfsmewCPQqPT, GkvqHDKUhHbpklP, M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}