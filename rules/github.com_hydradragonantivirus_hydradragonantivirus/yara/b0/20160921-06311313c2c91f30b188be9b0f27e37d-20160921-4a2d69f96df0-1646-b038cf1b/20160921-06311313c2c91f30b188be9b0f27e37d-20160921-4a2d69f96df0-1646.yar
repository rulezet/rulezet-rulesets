rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_1646 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash4       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"
    hash5       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1  = "turn \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})()," ascii
    $s2  = "{return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii
    $s3  = "return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})()," ascii
    $s4  = "0(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";" ascii
    $s5  = "n \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s6  = "Xg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function " ascii
    $s7  = "ction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s8  = "TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s9  = "rn \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s10 = "f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq" ascii
    $s11 = "){return \"KDh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}