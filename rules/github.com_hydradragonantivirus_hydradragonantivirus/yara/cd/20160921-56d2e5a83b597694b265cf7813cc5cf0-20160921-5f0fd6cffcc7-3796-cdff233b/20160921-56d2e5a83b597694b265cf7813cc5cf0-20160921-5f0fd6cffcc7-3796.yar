rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_5f0fd6cffcc7_3796 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_6d9213179dbb863530a638df47003a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"

  strings:
    $s1 = "g\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s2 = "\"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s4 = "{return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(" ascii
    $s5 = "(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";}" ascii
    $s6 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}