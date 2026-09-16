rule sig_20160520_ab0c815ffc7f28c2cb4f20345937ebf4 {
  meta:
    description = "datamaliciousorder - file 20160520_ab0c815ffc7f28c2cb4f20345937ebf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c1b29485a5a59bb4c454e4abcc768684b4ec607a00cf9bca44788df1e7a2864"

  strings:
    $s1  = "function kUKVNLWW(Azotj) {var AkraIKtJ=UhOmQwvZqoA[2];for(var nmGwi=0;nmGwi<Azotj;nmGwi++){NIYLN+=AkraIKtJ.charAt(Math.floor(Mat" ascii
    $s2  = "function kUKVNLWW(Azotj) {var AkraIKtJ=UhOmQwvZqoA[2];for(var nmGwi=0;nmGwi<Azotj;nmGwi++){NIYLN+=AkraIKtJ.charAt(Math.floor(Mat" ascii
    $s3  = "WQ.length;OXvRgdrV++) {BfdXQgE+=FSprs[pBcrWQ[OXvRgdrV]];}return BfdXQgE.substring(3,BfdXQgE.length);}" fullword ascii
    $s4  = "function XRHBVdjMb(FkSOOwDiy,kINQNZC,tOVamAod){" fullword ascii
    $s5  = "function AZWI(YQAeIY,ADQpTKh){idFR = UhOmQwvZqoA[11].split(UhOmQwvZqoA[12]);ADQpTKh.open(idFR[0]+idFR[2]+idFR[3], YQAeIY, false)" ascii
    $s6  = "function AdNqq(VBqtIi){return new ActiveXObject(VBqtIi);}" fullword ascii
    $s7  = "function FoaZJg(VBqtIi){return VBqtIi.ExpandEnvironmentStrings(UhOmQwvZqoA[10])}" fullword ascii
    $s8  = "function hAGxY(cbnpMCHL,pBcrWQ,xMrMqbOiG){FSprs=cbnpMCHL.split(xMrMqbOiG);BfdXQgE = UhOmQwvZqoA[13];for(OXvRgdrV=0;OXvRgdrV<pBcr" ascii
    $s9  = "h.random()*AkraIKtJ.length));}return NIYLN;}" fullword ascii
    $s10 = "if (ZNouOkh==0) break;" fullword ascii
    $s11 = "function AZWI(YQAeIY,ADQpTKh){idFR = UhOmQwvZqoA[11].split(UhOmQwvZqoA[12]);ADQpTKh.open(idFR[0]+idFR[2]+idFR[3], YQAeIY, false)" ascii
    $s12 = "function tKOOr(PHsariQe,INpQE,vuUyEiChol){PHsariQe.open();PHsariQe.type = 1;PHsariQe.write(INpQE);PHsariQe.position = 0;PHsariQe" ascii
    $s13 = "function HfziBcb() {var ESqh=100000;var mkGhGK = 100;return Math.random()*(ESqh-mkGhGK)+mkGhGK;}" fullword ascii
    $s14 = "try{ZNouOkh=XRHBVdjMb(JgnHa[TUbJ], HfziBcb() + UhOmQwvZqoA[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function hAGxY(cbnpMCHL,pBcrWQ,xMrMqbOiG){FSprs=cbnpMCHL.split(xMrMqbOiG);BfdXQgE = UhOmQwvZqoA[13];for(OXvRgdrV=0;OXvRgdrV<pBcr" ascii
    $s16 = "function tKOOr(PHsariQe,INpQE,vuUyEiChol){PHsariQe.open();PHsariQe.type = 1;PHsariQe.write(INpQE);PHsariQe.position = 0;PHsariQe" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}