rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160922_b9c8ae1e2648_405 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = "){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2  = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s3  = "Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s4  = " f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"G" ascii
    $s5  = "unction f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s6  = " \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s7  = "urn \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s8  = "rn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s9  = "nction f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s10 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f0" ascii
    $s11 = " f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"T" ascii
    $s12 = "nction f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s13 = "o\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s14 = "n f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"G" ascii
    $s15 = "rn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s16 = "){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})" ascii
    $s17 = "nction f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s18 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s19 = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(" ascii
    $s20 = "0(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}