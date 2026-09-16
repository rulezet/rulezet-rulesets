rule sig_20160909_fc11515d422c25448630fca3efcf04ae {
  meta:
    description = "datamaliciousorder - file 20160909_fc11515d422c25448630fca3efcf04ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "457798d5ef7bddfdb0acde1fd46fdb1aff74e8c4e352e9a8ab51d9fb73d84161"

  strings:
    $s1  = "function RAT()" fullword ascii
    $s2  = "return K;" fullword ascii
    $s3  = "return rg(Zf, XW, QO, zLH);" fullword ascii
    $s4  = "return (y(I, XW));" fullword ascii
    $s5  = "return eval(sKX);" fullword ascii
    $s6  = "function ej(APC)" fullword ascii
    $s7  = "function y(An, XW)" fullword ascii
    $s8  = "function J (mc)" fullword ascii
    $s9  = "return (n(I));" fullword ascii
    $s10 = "function kF(Q)" fullword ascii
    $s11 = "function rg(An, XW, QO, zLH)" fullword ascii
    $s12 = "return lK;" fullword ascii
    $s13 = "return Jz;" fullword ascii
    $s14 = "function d(adE, XW, QO, zLH)" fullword ascii
    $s15 = "return yrH;" fullword ascii
    $s16 = "return d(hi, XW, QO, YQq);" fullword ascii
    $s17 = "return (rg(I, XW, QO, zLH));" fullword ascii
    $s18 = "return Aid == cN;" fullword ascii
    $s19 = "function n(An)" fullword ascii
    $s20 = "} catch (dKo) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}