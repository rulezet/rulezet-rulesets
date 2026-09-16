rule sig_20160525_2dfbde314ec32320fd53f20cb67d3b79 {
  meta:
    description = "datamaliciousorder - file 20160525_2dfbde314ec32320fd53f20cb67d3b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88add8e9d777bb48866e1cc94393cf87f4d1aa9305187957da7a97bdfb8a5e90"

  strings:
    $s1  = ".pow(Math.cos(776), 2) - 1))-487)) OavYy += qDuDkGSWIBPfyx(OwJGHC, WPphTYbqdbnDWzsOSpYwkai);else OavYy += gymQnledSOiXu(OwJGHC, " ascii
    $s2  = "function ZnulFuQ(CsvrOcFnuBCJo) {var iwgpiSWxTOXJJrIiBuyPQPQ = kgxVpCTFqRSQNDPIAWqXJF.join(sXQzQi[0]);var OwJGHC, WPphTYbqdbnDWz" ascii
    $s3  = "ath.pow(Math.cos(616), 2) - 1))-672)) OavYy += Tw(OwJGHC);else if (nLCwK == (551 + Math.round((Math.pow(Math.sin(776), 2) + Math" ascii
    $s4  = "WPphTYbqdbnDWzsOSpYwkai, weFnccraXWhOmxh);} while (zMiKEdlckWNWtxhZHoNv < CsvrOcFnuBCJo.length);return OavYy;}" fullword ascii
    $s5  = "function jjvJJAZsKSDcVtqqJsRxuF(DSDElpHaaVkKWRFBVGKBX,sWbCfsmdClnVKyC){return DSDElpHaaVkKWRFBVGKBX.charAt(sWbCfsmdClnVKyC);}" fullword ascii
    $s6  = "function gymQnledSOiXu(NrsWueAnRVqcBkpfPzydDqp,ejWdgHShkTvfgTUFQtcjB,pXHdmYTQzLMI){return String.fromCharCode(NrsWueAnRVqcBkpfPz" ascii
    $s7  = "function Tw(CptrGFkdZmrg){return String.fromCharCode(CptrGFkdZmrg);}" fullword ascii
    $s8  = "function UTwbUKrvyd(vckEpmvAmxnv,iyqYCyzTklaffvJVqWZue){return vckEpmvAmxnv.indexOf(iyqYCyzTklaffvJVqWZue);}" fullword ascii
    $s9  = "function ZnulFuQ(CsvrOcFnuBCJo) {var iwgpiSWxTOXJJrIiBuyPQPQ = kgxVpCTFqRSQNDPIAWqXJF.join(sXQzQi[0]);var OwJGHC, WPphTYbqdbnDWz" ascii
    $s10 = "function gymQnledSOiXu(NrsWueAnRVqcBkpfPzydDqp,ejWdgHShkTvfgTUFQtcjB,pXHdmYTQzLMI){return String.fromCharCode(NrsWueAnRVqcBkpfPz" ascii
    $s11 = "function qDuDkGSWIBPfyx(cWUzeLOYKOcAo,NWtGbjH){return String.fromCharCode(cWUzeLOYKOcAo,NWtGbjH);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}