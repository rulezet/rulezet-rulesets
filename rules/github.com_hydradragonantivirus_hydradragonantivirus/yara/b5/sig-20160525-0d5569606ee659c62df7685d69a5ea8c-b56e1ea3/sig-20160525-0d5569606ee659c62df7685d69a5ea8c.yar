rule sig_20160525_0d5569606ee659c62df7685d69a5ea8c {
  meta:
    description = "datamaliciousorder - file 20160525_0d5569606ee659c62df7685d69a5ea8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8453690d98c554b156518dcceddfb4a0b30dc6a4708c9606a83b15588164aa8c"

  strings:
    $s1 = "function tTUqlm(aGrkwTumQGoAL) {var xtqEdRqtdqJYdrlC = XugZfwLDnuQ.join(BeXadpFDtTvOvSodcBMSsfe[0]);var AOubPuqJrViG, rzFvHfOl, " ascii
    $s2 = "(Math.pow(Math.sin(407), 2) + Math.pow(Math.cos(407), 2) - 1))-675)) EjwAYeH += Har(AOubPuqJrViG);else if (iMmjttrsMFyRho == (98" ascii
    $s3 = "function huvhXRSeZJNrWSw(UuQopZXeCqaV,hPqhyRFM){return UuQopZXeCqaV.charAt(hPqhyRFM);}" fullword ascii
    $s4 = "function DlJqhXBdZ(pbAxxYwOGBU,nILtVtxcx,ihYXxsDccj){return String.fromCharCode(pbAxxYwOGBU,nILtVtxcx,ihYXxsDccj);}" fullword ascii
    $s5 = "function fidvPYhRdKkNbiWfeVcv(vdQDwBVflwjBwUqtxVYXr,TwDUun){return vdQDwBVflwjBwUqtxVYXr.indexOf(TwDUun);}" fullword ascii
    $s6 = "function tTUqlm(aGrkwTumQGoAL) {var xtqEdRqtdqJYdrlC = XugZfwLDnuQ.join(BeXadpFDtTvOvSodcBMSsfe[0]);var AOubPuqJrViG, rzFvHfOl, " ascii
    $s7 = "function sdZitDwA(DvUCot,chSKyOUILPBpy){return String.fromCharCode(DvUCot,chSKyOUILPBpy);}" fullword ascii
    $s8 = "function Har(GkFjVnNlKZZCMShpXl){return String.fromCharCode(GkFjVnNlKZZCMShpXl);}" fullword ascii
    $s9 = "else EjwAYeH += DlJqhXBdZ(AOubPuqJrViG, rzFvHfOl, mFspuzwsGxUAdGxobszqDSKq);} while (EelPu < aGrkwTumQGoAL.length);return EjwAYe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}