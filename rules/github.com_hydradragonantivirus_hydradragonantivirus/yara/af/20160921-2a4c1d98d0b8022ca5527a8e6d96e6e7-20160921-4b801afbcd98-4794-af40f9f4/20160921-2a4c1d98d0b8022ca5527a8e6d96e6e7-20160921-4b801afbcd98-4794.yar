rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_4b801afbcd98_4794 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"

  strings:
    $s1 = "h\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s2 = "turn \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(f" ascii
    $s3 = "unction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){retu" ascii
    $s4 = "turn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}