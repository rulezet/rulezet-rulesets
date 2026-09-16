rule sig_20160527_68fe2aabfceeb6b49d48e18d631d4d87 {
  meta:
    description = "datamaliciousorder - file 20160527_68fe2aabfceeb6b49d48e18d631d4d87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ecac4a7d823ceab2004a6d126a4fe9678cf461bec1e28584177babbd3520d1"

  strings:
    $s1  = "function AoHwb() {return WScript;}function AGGuZjtadiPly(){return uakQajtKOKFr.ExpandEnvironmentStrings(oolwUzhBxdU())}" fullword ascii
    $s2  = "function AGlJXzDyoqH(zJJOnMFVdyOlopCiylMrDO,hrUeoMX){return zJJOnMFVdyOlopCiylMrDO.charAt(hrUeoMX);}" fullword ascii
    $s3  = "+= XCMoH(qLzIZwlNlpEUf, lLroGvGYLpJgLscwPAw, qIgtKVJAdCrilEjSbFgFPFJ);} while (SKCgOu < DnKBlRUbpMqrs.length);return CtmwSb;}" fullword ascii
    $s4  = "function ckMQWYdKgpVBSXFkcHvg(fPJmFtOPSJCynsSWj,PzSsBggDHAMSflxosymnIreE){return String.fromCharCode(fPJmFtOPSJCynsSWj,PzSsBggDH" ascii
    $s5  = "function IPlTonUkPksr(DnKBlRUbpMqrs) {var BGaRYtSEF = UyIyaDah.join(RPigNrrijm[6]);var qLzIZwlNlpEUf, lLroGvGYLpJgLscwPAw, qIgtK" ascii
    $s6  = "function IPlTonUkPksr(DnKBlRUbpMqrs) {var BGaRYtSEF = UyIyaDah.join(RPigNrrijm[6]);var qLzIZwlNlpEUf, lLroGvGYLpJgLscwPAw, qIgtK" ascii
    $s7  = "function XCMoH(vUnitivtejdfqBURaey,oLWlSSzUsjEeHmyUirgMFdy,YhcSysmDSqiueK){return String.fromCharCode(vUnitivtejdfqBURaey,oLWlSS" ascii
    $s8  = "function XCMoH(vUnitivtejdfqBURaey,oLWlSSzUsjEeHmyUirgMFdy,YhcSysmDSqiueK){return String.fromCharCode(vUnitivtejdfqBURaey,oLWlSS" ascii
    $s9  = "function ckMQWYdKgpVBSXFkcHvg(fPJmFtOPSJCynsSWj,PzSsBggDHAMSflxosymnIreE){return String.fromCharCode(fPJmFtOPSJCynsSWj,PzSsBggDH" ascii
    $s10 = "var AdwzcNTeGPxOoq = INVYlrs.createtextfile(uakQajtKOKFr.ExpandEnvironmentStrings(RPigNrrijm[2]+RPigNrrijm[3])+String.fromCharCo" ascii
    $s11 = "function klysQYOOuGiFNa(WsBrtwHMnQ,RvXFScPQavV,ZhrIItmGC){iiHKYaJWc=WsBrtwHMnQ.split(ZhrIItmGC);EYMXvlMIrPgLWA = RPigNrrijm[14];" ascii
    $s12 = "= N(qLzIZwlNlpEUf);else if (YDJCjqjEkvMjE == 64) CtmwSb += ckMQWYdKgpVBSXFkcHvg(qLzIZwlNlpEUf, lLroGvGYLpJgLscwPAw);else CtmwSb " ascii
    $s13 = "function QiVvhTYBcSO(WYXwARgxAu,cDcXJ) {var HSxpgGIlpndN=[RPigNrrijm[15]];WYXwARgxAu[HSxpgGIlpndN[0]](cDcXJ,0x1,0x0)}" fullword ascii
    $s14 = "function BDiLdVNvZpyl(lFSCDryVTCOogzODVCd,qtDAKvpqCELp){return lFSCDryVTCOogzODVCd.indexOf(qtDAKvpqCELp);}" fullword ascii
    $s15 = "function klysQYOOuGiFNa(WsBrtwHMnQ,RvXFScPQavV,ZhrIItmGC){iiHKYaJWc=WsBrtwHMnQ.split(ZhrIItmGC);EYMXvlMIrPgLWA = RPigNrrijm[14];" ascii
    $s16 = "var uakQajtKOKFr=function(){return AoHwb().CreateObject(RPigNrrijm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "for(qobJg=0;qobJg<RvXFScPQavV.length;qobJg++) {EYMXvlMIrPgLWA+=iiHKYaJWc[RvXFScPQavV[qobJg]];}return EYMXvlMIrPgLWA.substring(3," ascii
    $s18 = "function EoifTwqmyygN(){return klysQYOOuGiFNa(RPigNrrijm[12],[0,3,6],RPigNrrijm[13]);}" fullword ascii
    $s19 = "function N(HElAYili){return String.fromCharCode(HElAYili);}" fullword ascii
    $s20 = "var INVYlrs=function(){return new ActiveXObject(RPigNrrijm[0]);}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}