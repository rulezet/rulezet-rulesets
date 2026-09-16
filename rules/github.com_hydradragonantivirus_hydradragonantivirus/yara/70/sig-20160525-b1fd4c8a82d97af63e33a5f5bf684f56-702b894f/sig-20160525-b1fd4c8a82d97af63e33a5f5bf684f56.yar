rule sig_20160525_b1fd4c8a82d97af63e33a5f5bf684f56 {
  meta:
    description = "datamaliciousorder - file 20160525_b1fd4c8a82d97af63e33a5f5bf684f56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "819b9866b907ac0e9a28f3b753f859524d8bce9a8839b1a373705eae3aef7f7d"

  strings:
    $s1  = "function wYihU(QiQigobDowPzG) {var kHktIKJtXJEhQ = ItrVpzBXnPMZp.join(pYTWVjr[0]);var PRjIEMuDgzgvSzwMZPuA, iPaEDyMrIOAoCTujpOFC" ascii
    $s2  = " += Dz(PRjIEMuDgzgvSzwMZPuA);else if (yrlmVsYRsIW == (548 + Math.round((Math.pow(Math.sin(935), 2) + Math.pow(Math.cos(935), 2) " ascii
    $s3  = "function nRVFPsEIrkMpOHRbSelvloL(sRXJruPWuIYvpjiye,vTmcBEWQaoS){return sRXJruPWuIYvpjiye.charAt(vTmcBEWQaoS);}" fullword ascii
    $s4  = "- 1))-484)) aykrBYKueVbLvfYFHM += NSAaYBlFnaRN(PRjIEMuDgzgvSzwMZPuA, iPaEDyMrIOAoCTujpOFCOdn);else aykrBYKueVbLvfYFHM += lMwfDiu" ascii
    $s5  = "azAKj(PRjIEMuDgzgvSzwMZPuA, iPaEDyMrIOAoCTujpOFCOdn, fufwflDu);} while (zcUmUe < QiQigobDowPzG.length);return aykrBYKueVbLvfYFHM" ascii
    $s6  = "function NSAaYBlFnaRN(JFYYGxDgsyETSaBu,mxENnAPexzI){return String.fromCharCode(JFYYGxDgsyETSaBu,mxENnAPexzI);}" fullword ascii
    $s7  = "function qJPadfmkSAbU(eSchxXX,lLWYDLiYPHdNxyZpV){return eSchxXX.indexOf(lLWYDLiYPHdNxyZpV);}" fullword ascii
    $s8  = "function lMwfDiuazAKj(MpecBMUyRGjYTjDlAEw,JADkDbR,LCIdrbsSIHkkJitYIQaHn){return String.fromCharCode(MpecBMUyRGjYTjDlAEw,JADkDbR," ascii
    $s9  = "function Dz(XLTrGibfzlZoKDO){return String.fromCharCode(XLTrGibfzlZoKDO);}" fullword ascii
    $s10 = "function wYihU(QiQigobDowPzG) {var kHktIKJtXJEhQ = ItrVpzBXnPMZp.join(pYTWVjr[0]);var PRjIEMuDgzgvSzwMZPuA, iPaEDyMrIOAoCTujpOFC" ascii
    $s11 = "function lMwfDiuazAKj(MpecBMUyRGjYTjDlAEw,JADkDbR,LCIdrbsSIHkkJitYIQaHn){return String.fromCharCode(MpecBMUyRGjYTjDlAEw,JADkDbR," ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}