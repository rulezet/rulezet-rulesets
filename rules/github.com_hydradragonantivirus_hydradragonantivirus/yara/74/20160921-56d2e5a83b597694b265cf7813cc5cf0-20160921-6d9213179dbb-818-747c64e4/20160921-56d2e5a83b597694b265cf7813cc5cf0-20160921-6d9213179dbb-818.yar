rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_6d9213179dbb_818 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash3       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash4       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash5       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = " \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s2  = "{return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii
    $s3  = "(),(function f000(){return \"Rh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000()" ascii
    $s4  = "ion f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s5  = "){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(" ascii
    $s6  = "on f000(){return \"Ml\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s7  = ";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s8  = ";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f" ascii
    $s9  = " f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GG" ascii
    $s10 = "),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s11 = "00(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\"" ascii
    $s12 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(functio" ascii
    $s13 = "return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})()," ascii
    $s14 = "){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})" ascii
    $s15 = "f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\"" ascii
    $s16 = "eturn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})()" ascii
    $s17 = "){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";" ascii
    $s18 = "),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){" ascii
    $s19 = " f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s20 = "n f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}