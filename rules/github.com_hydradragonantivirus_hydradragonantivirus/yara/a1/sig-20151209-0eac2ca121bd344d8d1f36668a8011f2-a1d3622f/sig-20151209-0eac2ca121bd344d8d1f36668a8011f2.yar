rule sig_20151209_0eac2ca121bd344d8d1f36668a8011f2 {
  meta:
    description = "datamaliciousorder - file 20151209_0eac2ca121bd344d8d1f36668a8011f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1539beb808a58f413d6b5b83e01576d2750b34f2c732121995950a6c3f50b08"

  strings:
    $s1  = "function HiwwKPs(SEiXTvdrprKOmVKLtyMHzLHRQEELcwcnMhnW) {return !isNaN(parseFloat(SEiXTvdrprKOmVKLtyMHzLHRQEELcwcnMhnW)) && isFin" ascii
    $s2  = "function HiwwKPs(SEiXTvdrprKOmVKLtyMHzLHRQEELcwcnMhnW) {return !isNaN(parseFloat(SEiXTvdrprKOmVKLtyMHzLHRQEELcwcnMhnW)) && isFin" ascii
    $s3  = "function FmvNg(zLtHneCZWRj,nOHPpeWfEwnyF,NKRMnGed){TrSR=parseInt(zLtHneCZWRj,nOHPpeWfEwnyF);hhnXQ=TrSR.toString(NKRMnGed);return" ascii
    $s4  = "function jdukLOfbTVZJQhTPI(EOrzR){qogqUOWHgfq= '';for(YNxYqOvOavl=(-656+656)/488; YNxYqOvOavl < (74+672)/373; YNxYqOvOavl++) {Vj" ascii
    $s5  = "function jdukLOfbTVZJQhTPI(EOrzR){qogqUOWHgfq= '';for(YNxYqOvOavl=(-656+656)/488; YNxYqOvOavl < (74+672)/373; YNxYqOvOavl++) {Vj" ascii
    $s6  = "function tLXAwAAlDYvyzYBXLwtlhpeAqPErJmANWSIfObRSqvSkWCfgovwpNr(iWrfpDstJQare,rBlUrsMYtZOlZQ){ return dBNxb[FmvNg(iWrfpDstJQare[" ascii
    $s7  = "ZtlIGDW[YNxYqOvOavl]=(-387+387)/78; while(true) { if(VjZtlIGDW[YNxYqOvOavl] > EOrzR[YNxYqOvOavl].length-(-37+216)/179) { break; " ascii
    $s8  = "function tLXAwAAlDYvyzYBXLwtlhpeAqPErJmANWSIfObRSqvSkWCfgovwpNr(iWrfpDstJQare,rBlUrsMYtZOlZQ){ return dBNxb[FmvNg(iWrfpDstJQare[" ascii
    $s9  = "}} return qogqUOWHgfq}" fullword ascii
    $s10 = "function FmvNg(zLtHneCZWRj,nOHPpeWfEwnyF,NKRMnGed){TrSR=parseInt(zLtHneCZWRj,nOHPpeWfEwnyF);hhnXQ=TrSR.toString(NKRMnGed);return" ascii
    $s11 = "function hXFhGKyIxgn(CfjbDSEH,gpwBhk){return CfjbDSEH.split(gpwBhk)}" fullword ascii
    $s12 = " hhnXQ;}function DXlZgcydrRuYObt(cpjTkYXHWmzXRpxEo){eval(cpjTkYXHWmzXRpxEo)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}