rule sig_20160531_4aad50dbce7be7ab9d285071fb3e63c4 {
  meta:
    description = "datamaliciousorder - file 20160531_4aad50dbce7be7ab9d285071fb3e63c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84650cede498014254a0373b4989b23d3791e58e32d72160b46eb8aa7640d083"

  strings:
    $s1  = "var vxkiZJgInSaJqW=function(){return WScript.CreateObject(KEsUd[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function GQTtLESYSksbONXuEc(HrVYn,NMNiHkoLoETXJcSFj){return HrVYn.charAt(NMNiHkoLoETXJcSFj);}" fullword ascii
    $s3  = "var giWiyterTYb=function(){return new ActiveXObject(KEsUd[1]);}();" fullword ascii
    $s4  = "function TscyMIrapjADg(EWxsCHgUMbcGG) {var bGwKhOLThVzOY = UVWZUKPYBpGmpIcvSHvrg.join(KEsUd[7]);var ZlQjDF, pOmmyzAaehMkoPHkvWDd" ascii
    $s5  = "(LqQPNkcQNcbXok,0x1,0x0)}function CUTww(YZIHQidulRF,EkiDFIixHglW,dvUgMfWgf){var TYxHGly=YZIHQidulRF.createtextfile(EkiDFIixHglW," ascii
    $s6  = "function lNLFGmHgheCrW(zdVrNVXWmiMZGAt,eCVTcf,FKWzzJreIjLDWSuWPHrBncPH){return String.fromCharCode(zdVrNVXWmiMZGAt,eCVTcf,FKWzzJ" ascii
    $s7  = "function THZgMUQGzA(sYMVhklblP,UkIfw){return sYMVhklblP.indexOf(UkIfw);}" fullword ascii
    $s8  = "function TscyMIrapjADg(EWxsCHgUMbcGG) {var bGwKhOLThVzOY = UVWZUKPYBpGmpIcvSHvrg.join(KEsUd[7]);var ZlQjDF, pOmmyzAaehMkoPHkvWDd" ascii
    $s9  = "cuS < EWxsCHgUMbcGG.length);return zLWhYmRMkY;}" fullword ascii
    $s10 = "function QvCiblOApEs(){return EZIPVzko(KEsUd[13],[0,3,6],KEsUd[14]);}" fullword ascii
    $s11 = "function yHizqClKPwNUO(){return EZIPVzko(KEsUd[11],[2,4,8,10],KEsUd[12]);}" fullword ascii
    $s12 = "function lWMiQ(){return vxkiZJgInSaJqW.ExpandEnvironmentStrings(xqSpqHQDzRhh())}" fullword ascii
    $s13 = "KzJXOPMFmRxLY<nsHsQAsyHKiWC.length;PKzJXOPMFmRxLY++) {cOOGNDc+=FLyYMm[nsHsQAsyHKiWC[PKzJXOPMFmRxLY]];}return cOOGNDc.substring(3" ascii
    $s14 = "(LqQPNkcQNcbXok,0x1,0x0)}function CUTww(YZIHQidulRF,EkiDFIixHglW,dvUgMfWgf){var TYxHGly=YZIHQidulRF.createtextfile(EkiDFIixHglW," ascii
    $s15 = "function QSYvwcmCblEFGVegyDuliY(nuLupF,VaTJTQJqHbdemNtDC){return String.fromCharCode(nuLupF,VaTJTQJqHbdemNtDC);}" fullword ascii
    $s16 = "function EZIPVzko(frhKnfgzRcqt,nsHsQAsyHKiWC,QhUPMI){FLyYMm=frhKnfgzRcqt.split(QhUPMI);cOOGNDc = KEsUd[0];for(PKzJXOPMFmRxLY=0;P" ascii
    $s17 = "function nZbqBS(eZZrirzDvd,LqQPNkcQNcbXok) {var ViNiswXwqQVrg=[KEsUd[15]];eZZrirzDvd[ViNiswXwqQVrg[0]]" fullword ascii
    $s18 = "xr & 0xff;if (HSEOSgG == 64) zLWhYmRMkY += ZS(ZlQjDF);else if (ZdXZnRdXPuzgeAQLLOS == 64) zLWhYmRMkY += QSYvwcmCblEFGVegyDuliY(Z" ascii
    $s19 = "function xqSpqHQDzRhh(){return EZIPVzko(KEsUd[9],[1,5,7],KEsUd[10]);}" fullword ascii
    $s20 = "true);TYxHGly.WriteLine(dvUgMfWgf);TYxHGly.Close();}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}