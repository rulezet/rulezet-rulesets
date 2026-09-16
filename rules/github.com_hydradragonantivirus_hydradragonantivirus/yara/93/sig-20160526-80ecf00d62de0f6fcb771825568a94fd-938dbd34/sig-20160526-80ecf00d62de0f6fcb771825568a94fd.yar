rule sig_20160526_80ecf00d62de0f6fcb771825568a94fd {
  meta:
    description = "datamaliciousorder - file 20160526_80ecf00d62de0f6fcb771825568a94fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fa81e57d8736786fbf2088586afe593bb5a34e30ce88c3f60bb8fb027419c25"

  strings:
    $s1  = "function FWURkRdiR(JNtZScjmGJtRs) {var yPAoDGhHiG = gTeeuPTpBgJoZ.join(YBnsgwnbIfSdGP[0]);var izuLnapdeUDw, KmwCJxIaHTuWVykBfXUJ" ascii
    $s2  = " 2) - 1))-954)) GNJVZzwuQTqsztTn += iLvyRcYKETCX(izuLnapdeUDw, KmwCJxIaHTuWVykBfXUJizbr);else GNJVZzwuQTqsztTn += gCdNhtrdAsBKof" ascii
    $s3  = "ztTn += dS(izuLnapdeUDw);else if (MaSiJYqoQPaDRsxabR == (1018 + Math.round((Math.pow(Math.sin(328), 2) + Math.pow(Math.cos(328)," ascii
    $s4  = "function fFdhH(JrTudpmbZnLuCoQsck,hDHEnZ){return JrTudpmbZnLuCoQsck.charAt(hDHEnZ);}" fullword ascii
    $s5  = "function dS(trimhAcGOFxouZiIepdxu){return String.fromCharCode(trimhAcGOFxouZiIepdxu);}" fullword ascii
    $s6  = "function FWURkRdiR(JNtZScjmGJtRs) {var yPAoDGhHiG = gTeeuPTpBgJoZ.join(YBnsgwnbIfSdGP[0]);var izuLnapdeUDw, KmwCJxIaHTuWVykBfXUJ" ascii
    $s7  = "function iLvyRcYKETCX(mcbVHzpJBc,WwUGSMy){return String.fromCharCode(mcbVHzpJBc,WwUGSMy);}" fullword ascii
    $s8  = "eOFNjlLSt(izuLnapdeUDw, KmwCJxIaHTuWVykBfXUJizbr, tzGgsErZOXXtDDVBSeUsJk);} while (FsXaGryLld < JNtZScjmGJtRs.length);return GNJ" ascii
    $s9  = "function gyNHexlFQJKBn(AETJhSuV,zycaBI){return AETJhSuV.indexOf(zycaBI);}" fullword ascii
    $s10 = "function gCdNhtrdAsBKofeOFNjlLSt(rkStosszWOsaTyp,AmLHDHuO,RcqcaBffzdklsWJlzDgxNiKk){return String.fromCharCode(rkStosszWOsaTyp,A" ascii
    $s11 = "function gCdNhtrdAsBKofeOFNjlLSt(rkStosszWOsaTyp,AmLHDHuO,RcqcaBffzdklsWJlzDgxNiKk){return String.fromCharCode(rkStosszWOsaTyp,A" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}