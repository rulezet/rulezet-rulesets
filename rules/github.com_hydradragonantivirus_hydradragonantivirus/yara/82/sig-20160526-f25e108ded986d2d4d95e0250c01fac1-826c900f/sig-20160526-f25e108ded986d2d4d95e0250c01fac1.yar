rule sig_20160526_f25e108ded986d2d4d95e0250c01fac1 {
  meta:
    description = "datamaliciousorder - file 20160526_f25e108ded986d2d4d95e0250c01fac1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2371e0be53177386b8ca5b8070c0d8f61459f60fbaabc17eb83edc146cb0e045"

  strings:
    $s1  = " + Math.pow(Math.cos(393), 2) - 1))-4)) EaTstfsnyc += HCnyrAOUEIysKRrZSYsOjo(LGSrctmEojlvLZgzmQYVjB, mwsccDbns);else EaTstfsnyc " ascii
    $s2  = "function qSTITzXHRJBiBh(pkgRGqZehQxat) {var GkkVxpHacwFERAeUslUwUid = TanQqVnARNDJY.join(QcgMaLorA[0]);var LGSrctmEojlvLZgzmQYVj" ascii
    $s3  = "))-443)) EaTstfsnyc += DF(LGSrctmEojlvLZgzmQYVjB);else if (JFMlkpUmzOlUjlwdmViFY == (68 + Math.round((Math.pow(Math.sin(393), 2)" ascii
    $s4  = "function uGmXaNqpyCpdIymZ(xHtFyrqiosMGU,HJgNIvF){return xHtFyrqiosMGU.charAt(HJgNIvF);}" fullword ascii
    $s5  = "function HCnyrAOUEIysKRrZSYsOjo(VJibDSJWIEeHSoHwUJJ,gFblETCzQgwwXWZg){return String.fromCharCode(VJibDSJWIEeHSoHwUJJ,gFblETCzQgw" ascii
    $s6  = "function lZVJNwIHmlNnlwQTVHqqKPyK(dkYUmBZnqZHIOyJexFeb,GFPCIfyZJbXicLiUD,sOQwUrzTXv){return String.fromCharCode(dkYUmBZnqZHIOyJe" ascii
    $s7  = ");return EaTstfsnyc;}" fullword ascii
    $s8  = "function qSTITzXHRJBiBh(pkgRGqZehQxat) {var GkkVxpHacwFERAeUslUwUid = TanQqVnARNDJY.join(QcgMaLorA[0]);var LGSrctmEojlvLZgzmQYVj" ascii
    $s9  = "+= lZVJNwIHmlNnlwQTVHqqKPyK(LGSrctmEojlvLZgzmQYVjB, mwsccDbns, yPiOkdBSavLANE);} while (EtBGaEDuwnlZJuNLM < pkgRGqZehQxat.length" ascii
    $s10 = "function aSBTQvYwPfuaq(ExEZYMS,WzEHUeuqCrQVvRt){return ExEZYMS.indexOf(WzEHUeuqCrQVvRt);}" fullword ascii
    $s11 = "function HCnyrAOUEIysKRrZSYsOjo(VJibDSJWIEeHSoHwUJJ,gFblETCzQgwwXWZg){return String.fromCharCode(VJibDSJWIEeHSoHwUJJ,gFblETCzQgw" ascii
    $s12 = "function lZVJNwIHmlNnlwQTVHqqKPyK(dkYUmBZnqZHIOyJexFeb,GFPCIfyZJbXicLiUD,sOQwUrzTXv){return String.fromCharCode(dkYUmBZnqZHIOyJe" ascii
    $s13 = "function DF(IbNujQjCTtPHCoogNJxNPcl){return String.fromCharCode(IbNujQjCTtPHCoogNJxNPcl);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}