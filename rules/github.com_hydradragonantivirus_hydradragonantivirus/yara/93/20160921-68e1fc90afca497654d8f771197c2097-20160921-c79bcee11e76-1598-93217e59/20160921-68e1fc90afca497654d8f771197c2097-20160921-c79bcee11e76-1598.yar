rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_c79bcee11e76_1598 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1  = "(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(" ascii
    $s2  = "eturn \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s3  = ";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f0" ascii
    $s4  = "n \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(fu" ascii
    $s5  = "turn \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"PTs\";})()," ascii
    $s6  = "ion f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s7  = "){return \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";}" ascii
    $s8  = "ion f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s9  = "nction f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s10 = "00(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn" ascii
    $s11 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})()," ascii
    $s12 = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}