rule sig_20160315_252c3613fd33f8e11d0a901eb7506952 {
  meta:
    description = "datamaliciousorder - file 20160315_252c3613fd33f8e11d0a901eb7506952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "909946197402090776df26b65a3b3eafecddb1766fc30a7ed31d662c0b331f99"

  strings:
    $s1 = "function gjdHeyegj(n){return dMUWEnT + tlZibrZDk + Lsm + CvjIggLgBqTiZ + zRHzkv + ipFDiqkRqZ + lIK;}" fullword ascii
    $s2 = "function cgRbejJDD(lmCEzYNSM){WshShell[llIXeROwl + oxAibjIUm](lmCEzYNSM, 0, 0);}" fullword ascii
    $s3 = "while (amBzDVjdx.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4 = " gFeYgRvS + DjOkmFbLAxg + fPAcXRY + aQjzDdKgciq + TlpDrLtFRuFn + PlBYladIoF, false);" fullword ascii
    $s5 = "amBzDVjdx[feN + YlIit](VZPBRa, HlIPYyFucJNd + rHScPWTWUxi + UrXQvQ + NAWVgAYWwWUTzTh + XgjkjuERhcbTRB + XfhE + sgngxa + PBcKCfQB" ascii
    $s6 = "var fuqT = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}