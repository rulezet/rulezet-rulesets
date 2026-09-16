rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_12 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1  = "n f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s2  = "\"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s3  = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return" ascii
    $s4  = "function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s5  = " f000(){return \"ZFe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"S" ascii
    $s6  = ",(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s7  = "return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})()," ascii
    $s8  = "00(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";" ascii
    $s9  = "ion f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Wb\";})()," ascii
    $s11 = "Xg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s12 = "on f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s13 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(fu" ascii
    $s14 = "n \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s15 = "Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s16 = "(),(function f000(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s17 = "urn \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s18 = ";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii
    $s19 = "ction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s20 = "0(){return \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}