rule sig_20160314_f08990c783cdcbc834fba31dd6ab30e9 {
  meta:
    description = "datamaliciousorder - file 20160314_f08990c783cdcbc834fba31dd6ab30e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c4b02bb08a0ac08462ce9291c3b0260ba2441a097d9a8acd65fe47af4eb85d0"

  strings:
    $s1 = "MVtqELiqESjJwC.open(vzNbpjP + FJD, qBrs + nPXKECKea + mFJ + hDLZno + ElXIRrXviGBsNI + lRO + olgF + yCTbtYbBgDq + aVRpFKQqdQfaEy " ascii
    $s2 = "while (MVtqELiqESjJwC.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function mEnZ(n)" fullword ascii
    $s4 = "OkKdB, false);" fullword ascii
    $s5 = "var cCIytLnNYEhPJjj = new Date();" fullword ascii
    $s6 = "function IjXrAwlv(fname)" fullword ascii
    $s7 = "return qZwTN + WiqUVYtI + yOOCasLoQfm + KrfMR + FNrbQkGFcjm + uaNZZklkOXVbeU" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}