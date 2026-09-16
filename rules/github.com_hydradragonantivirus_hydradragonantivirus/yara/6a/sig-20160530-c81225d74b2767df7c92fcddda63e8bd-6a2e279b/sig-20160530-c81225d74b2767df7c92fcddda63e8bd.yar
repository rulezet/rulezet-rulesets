rule sig_20160530_c81225d74b2767df7c92fcddda63e8bd {
  meta:
    description = "datamaliciousorder - file 20160530_c81225d74b2767df7c92fcddda63e8bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "082c79e7d9cc92047f6e73e924af871fcfe588ad6a473b1d611e6df78a72ddff"

  strings:
    $s1  = "var actMamoy=function(){return WScript.CreateObject(GPMurEYhwMAKUf[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function AgJLz(LoLJMCLpFrDhXvhJRfXXaWO,fDKbhkwnTIDJFuVXP){return LoLJMCLpFrDhXvhJRfXXaWO.charAt(fDKbhkwnTIDJFuVXP);}" fullword ascii
    $s3  = "zBGzJzZdFsoLdjZ == 64) dYxtrzwhVBGSlwLhFLrqBbB += Iu(zMBspkUBL);else if (DyMijOQUilTDWiHkQ == 64) dYxtrzwhVBGSlwLhFLrqBbB += rcL" ascii
    $s4  = "function Iu(kWKjpZTnrCpkbLMGrHZLa){return String.fromCharCode(kWKjpZTnrCpkbLMGrHZLa);}" fullword ascii
    $s5  = "function MbrpiNt(Cedif,xcqzJYniKY,hAAeGit){eePIel=Cedif.split(hAAeGit);RVXGFGR = GPMurEYhwMAKUf[0];for(VQHrTOyWMNRZeG=0;VQHrTOyW" ascii
    $s6  = "function rcLjBwepvYUAqClTN(IFSChUnvNyHBVvY,dRrCWdbBtnHuUoqL){return String.fromCharCode(IFSChUnvNyHBVvY,dRrCWdbBtnHuUoqL);}" fullword ascii
    $s7  = "function KlUNilzJH(){return actMamoy.ExpandEnvironmentStrings(POPfpSHWPMk())}" fullword ascii
    $s8  = "jBwepvYUAqClTN(zMBspkUBL, UWuICdQutd);else dYxtrzwhVBGSlwLhFLrqBbB += RaVjjKpaXGUl(zMBspkUBL, UWuICdQutd, JykyfqTZoMnkcrYAYirKkk" ascii
    $s9  = "function MbrpiNt(Cedif,xcqzJYniKY,hAAeGit){eePIel=Cedif.split(hAAeGit);RVXGFGR = GPMurEYhwMAKUf[0];for(VQHrTOyWMNRZeG=0;VQHrTOyW" ascii
    $s10 = "function aLsnNuaGESIIMJ(RWxSe,mPvzuArPQwGDz) {var YyNwhYkRT=[GPMurEYhwMAKUf[15]];RWxSe[YyNwhYkRT[0]]" fullword ascii
    $s11 = "function RaVjjKpaXGUl(UfHwvUDPhbDpbCQRKgwraB,eAcksMYwsEPtzGPWhdJpZVRO,VUpIMkvmMTsCLwZGkLSBQB){return String.fromCharCode(UfHwvUD" ascii
    $s12 = "function LGRMG(){return MbrpiNt(GPMurEYhwMAKUf[13],[0,3,6],GPMurEYhwMAKUf[14]);}" fullword ascii
    $s13 = "function bDrceZupwf(){return MbrpiNt(GPMurEYhwMAKUf[11],[2,4,8,10],GPMurEYhwMAKUf[12]);}" fullword ascii
    $s14 = "var UgaoNfpngOI = SkONOYHuJ.createtextfile(actMamoy.ExpandEnvironmentStrings(GPMurEYhwMAKUf[3]+GPMurEYhwMAKUf[4])+String.fromCha" ascii
    $s15 = "MNRZeG<xcqzJYniKY.length;VQHrTOyWMNRZeG++) {RVXGFGR+=eePIel[xcqzJYniKY[VQHrTOyWMNRZeG]];}return RVXGFGR.substring(3,RVXGFGR.leng" ascii
    $s16 = "var SkONOYHuJ=function(){return new ActiveXObject(GPMurEYhwMAKUf[1]);}();" fullword ascii
    $s17 = "function RaVjjKpaXGUl(UfHwvUDPhbDpbCQRKgwraB,eAcksMYwsEPtzGPWhdJpZVRO,VUpIMkvmMTsCLwZGkLSBQB){return String.fromCharCode(UfHwvUD" ascii
    $s18 = "rCode(92)+GPMurEYhwMAKUf[5],true);" fullword ascii
    $s19 = "function WacorzJqQu(gGurdfJNvwUdXxkmsew,wWTwloxMuHWYwknqWLSZ){return gGurdfJNvwUdXxkmsew.indexOf(wWTwloxMuHWYwknqWLSZ);}" fullword ascii
    $s20 = "function POPfpSHWPMk(){return MbrpiNt(GPMurEYhwMAKUf[9],[1,5,7],GPMurEYhwMAKUf[10]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}