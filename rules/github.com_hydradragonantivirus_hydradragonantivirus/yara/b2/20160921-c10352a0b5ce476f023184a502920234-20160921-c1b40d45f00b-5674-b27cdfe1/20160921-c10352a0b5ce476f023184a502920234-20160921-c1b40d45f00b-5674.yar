rule _20160921_c10352a0b5ce476f023184a502920234_20160921_c1b40d45f00b_5674 {
  meta:
    description = "datamaliciousorder - from files 20160921_c10352a0b5ce476f023184a502920234.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = "\"KXg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(funct" ascii
    $s2 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii
    $s3 = "(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";" ascii
    $s4 = "KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s5 = "nction f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}