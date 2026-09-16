rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_47da6150745e_1688 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1  = "nction f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s2  = "ion f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s3  = "){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})" ascii
    $s4  = "n f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return " ascii
    $s5  = "unction f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){retu" ascii
    $s6  = "ion f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s7  = "),(function f000(){return \"DYx\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Oe\";})(),(function f000(){" ascii
    $s8  = "000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s9  = "on f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"" ascii
    $s10 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii
    $s11 = "){return \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}