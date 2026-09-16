rule sig_20151216_1298b34a7b075f4dbe75c8e634ebad6d {
  meta:
    description = "datamaliciousorder - file 20151216_1298b34a7b075f4dbe75c8e634ebad6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5564e42ef26f783127e287fa1beca257800eb91c2e1b5efa7e9b9347152208b7"

  strings:
    $s1  = ") - 1));while(true){if (lmbZFqvpoLG >= (1576+554)/355){break;}lVssEhnBC[lmbZFqvpoLG]=Math.round((Math.pow(Math.sin(627), 2) + Ma" ascii
    $s2  = "function dXXeeubcuBqaRJBDO(HzjKO){eLmDTlgxYCw= '';lmbZFqvpoLG=Math.round((Math.pow(Math.sin(689), 2) + Math.pow(Math.cos(689), 2" ascii
    $s3  = "th.pow(Math.cos(627), 2) - 1)); while(true) { if(lVssEhnBC[lmbZFqvpoLG] > HzjKO[lmbZFqvpoLG].length-(-514+833)/319) { break; } i" ascii
    $s4  = ".pow(Math.cos(972), 2) - 1)));} lVssEhnBC[lmbZFqvpoLG]++;}lmbZFqvpoLG++;} return eLmDTlgxYCw}" fullword ascii
    $s5  = "function dXXeeubcuBqaRJBDO(HzjKO){eLmDTlgxYCw= '';lmbZFqvpoLG=Math.round((Math.pow(Math.sin(689), 2) + Math.pow(Math.cos(689), 2" ascii
    $s6  = "LlXkYlFVeHrexQMTmDvbVTQtTpDPUUjHJCUa([HzjKO[lmbZFqvpoLG][lVssEhnBC[lmbZFqvpoLG]]], Math.round((Math.pow(Math.sin(972), 2) + Math" ascii
    $s7  = "function CrTNAsu(mdykKhUIvJBFdbVHbTwhqPyfIkSbBTMCtiUl) {return !ZWWYnBKwgFk(GWXYUkrDQOapQNl(mdykKhUIvJBFdbVHbTwhqPyfIkSbBTMCtiUl" ascii
    $s8  = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s9  = "function UydhswFYcfTsYHOaCKLlXkYlFVeHrexQMTmDvbVTQtTpDPUUjHJCUa(JhXcWhaTtKahy,bqOoPumDaVwRnu){ return fUBjgCm[XpEbyrQx[VatNn(JhX" ascii
    $s10 = "function VatNn(TKNSoJFHieH,hkhwpOEADzhEy,csnUPoLO){WOKF=pNLwfxcRqDHrzPVkG(TKNSoJFHieH,hkhwpOEADzhEy);yOBjT=WOKF.toString(csnUPoL" ascii
    $s11 = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s12 = "function EUWcJSvXewkN(EfKFOOYBBMrdD) {return isFinite(EfKFOOYBBMrdD);}" fullword ascii
    $s13 = "function UydhswFYcfTsYHOaCKLlXkYlFVeHrexQMTmDvbVTQtTpDPUUjHJCUa(JhXcWhaTtKahy,bqOoPumDaVwRnu){ return fUBjgCm[XpEbyrQx[VatNn(JhX" ascii
    $s14 = "function VooeETFdTfeolhc(OhdFKikQqMdanGIEJ,CMBOWvISEjyBWtfEERbRQZdTQutBIXPsZC,VnvIMhtvJyFOZaUTKfQvJUrOIsSALGhSVkC){eval(OhdFKikQ" ascii
    $s15 = "function pNLwfxcRqDHrzPVkG(rsxKExQChW,fVmmTKtFQS) {return parseInt(rsxKExQChW,fVmmTKtFQS);}" fullword ascii
    $s16 = "function ZWWYnBKwgFk(nRFBzhaCKWPZNY) {return isNaN(nRFBzhaCKWPZNY);}" fullword ascii
    $s17 = "function VooeETFdTfeolhc(OhdFKikQqMdanGIEJ,CMBOWvISEjyBWtfEERbRQZdTQutBIXPsZC,VnvIMhtvJyFOZaUTKfQvJUrOIsSALGhSVkC){eval(OhdFKikQ" ascii
    $s18 = "O);return yOBjT;}" fullword ascii
    $s19 = "function u(RxKdoXKwvxrchs,wOijeYLpXxTez,OBObrUjwvJj) {RxKdoXKwvxrchs[wOijeYLpXxTez]=OBObrUjwvJj;}" fullword ascii
    $s20 = "function GWXYUkrDQOapQNl(CxUWBPHbMcNEsFDRsYn) {return parseFloat(CxUWBPHbMcNEsFDRsYn);}" fullword ascii

  condition:
    uint16(0) == 0x7058 and
    8 of them
}