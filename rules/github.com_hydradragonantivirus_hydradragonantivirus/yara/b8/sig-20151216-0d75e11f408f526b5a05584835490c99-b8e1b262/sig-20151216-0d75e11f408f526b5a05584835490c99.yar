rule sig_20151216_0d75e11f408f526b5a05584835490c99 {
  meta:
    description = "datamaliciousorder - file 20151216_0d75e11f408f526b5a05584835490c99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14875573d057c10939e95346da5aa51ed3c85c6139033af83190724cc2b664a2"

  strings:
    $s1  = "h.pow(Math.cos(108), 2) - 1)); while(true) { if(ykpLKeGPl[MXRnWFlVkFf] > THoWx[MXRnWFlVkFf].length-(666+224)/890) { break; } if " ascii
    $s2  = ") - 1));while(true){if (MXRnWFlVkFf >= (407+811)/203){break;}ykpLKeGPl[MXRnWFlVkFf]=Math.round((Math.pow(Math.sin(108), 2) + Mat" ascii
    $s3  = "(Math.cos(729), 2) - 1)));} ykpLKeGPl[MXRnWFlVkFf]++;}MXRnWFlVkFf++;} return NzAEADVcZBN}" fullword ascii
    $s4  = "function xpzHCFRBghQDJDCPd(THoWx){NzAEADVcZBN= '';MXRnWFlVkFf=Math.round((Math.pow(Math.sin(570), 2) + Math.pow(Math.cos(570), 2" ascii
    $s5  = "function xpzHCFRBghQDJDCPd(THoWx){NzAEADVcZBN= '';MXRnWFlVkFf=Math.round((Math.pow(Math.sin(570), 2) + Math.pow(Math.cos(570), 2" ascii
    $s6  = "function HDUOPrz(SQemiIaiKwZWlAWLOvScIZaQAaVPdxxiSaiw) {return !FrJhMjfMJTV(fAfWUhjPfCWZnxD(SQemiIaiKwZWlAWLOvScIZaQAaVPdxxiSaiw" ascii
    $s7  = "function tDrMhHmHNiwspFO(dtcJVvcIGGWKtWRtC,pdBJktkPHbYiGHKZPVPfXRdKMlMZHFKJLY,ZnTpGkRHBAEyMcHxhbcWfUORNLzFAPgBAPU){eval(dtcJVvcI" ascii
    $s8  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s9  = "function eejYdPmelYlOHLsuh(LEBwHQqNaT,VNEbyHJLrW) {return parseInt(LEBwHQqNaT,VNEbyHJLrW);}" fullword ascii
    $s10 = "function jQolRjMegukCxRXmmJbBCoqkKfHfdNaigUwKJyPLdmZZbwFQiFxyGB(jewzEemZvcRYH,VJgSCGhBtqlMjt){ return indlGew[nXXvpLvk[DjflJ(jew" ascii
    $s11 = "function DjflJ(DkvoTLcSvfZ,eyTJkQgWWKmjm,idWuprEW){liSd=eejYdPmelYlOHLsuh(DkvoTLcSvfZ,eyTJkQgWWKmjm);XmXBL=liSd.toString(idWuprE" ascii
    $s12 = "function FrJhMjfMJTV(AglEIqnFkEKwlJ) {return isNaN(AglEIqnFkEKwlJ);}" fullword ascii
    $s13 = "function tDrMhHmHNiwspFO(dtcJVvcIGGWKtWRtC,pdBJktkPHbYiGHKZPVPfXRdKMlMZHFKJLY,ZnTpGkRHBAEyMcHxhbcWfUORNLzFAPgBAPU){eval(dtcJVvcI" ascii
    $s14 = "function fAfWUhjPfCWZnxD(IDzIHDwMJDdmLrzqEgX) {return parseFloat(IDzIHDwMJDdmLrzqEgX);}" fullword ascii
    $s15 = "function w(RfDbSeSuqrwx,hoCveuGaGTDLPP){RfDbSeSuqrwx.push(hoCveuGaGTDLPP);}" fullword ascii
    $s16 = "function DjflJ(DkvoTLcSvfZ,eyTJkQgWWKmjm,idWuprEW){liSd=eejYdPmelYlOHLsuh(DkvoTLcSvfZ,eyTJkQgWWKmjm);XmXBL=liSd.toString(idWuprE" ascii
    $s17 = "function lKxlTzcgwuOc(reHtbfObxKxDm) {return isFinite(reHtbfObxKxDm);}" fullword ascii
    $s18 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s19 = "function A(xgLTgRuzQuqScu,zRXpELSoNYeVN,DkoPaLxecDT) {xgLTgRuzQuqScu[zRXpELSoNYeVN]=DkoPaLxecDT;}" fullword ascii
    $s20 = "function HDUOPrz(SQemiIaiKwZWlAWLOvScIZaQAaVPdxxiSaiw) {return !FrJhMjfMJTV(fAfWUhjPfCWZnxD(SQemiIaiKwZWlAWLOvScIZaQAaVPdxxiSaiw" ascii

  condition:
    uint16(0) == 0x586e and
    8 of them
}