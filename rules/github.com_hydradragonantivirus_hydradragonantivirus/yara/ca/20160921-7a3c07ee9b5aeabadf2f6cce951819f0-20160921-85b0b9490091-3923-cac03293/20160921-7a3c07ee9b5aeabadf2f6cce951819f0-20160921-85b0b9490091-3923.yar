rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_85b0b9490091_3923 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_85b0b94900915170fd854268d8d17fd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"

  strings:
    $s1 = "000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s2 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s3 = "n f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn" ascii
    $s5 = "f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn" ascii
    $s6 = "n f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}