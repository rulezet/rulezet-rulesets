rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_1de6da840ee5_4294 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash3       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"

  strings:
    $s1 = "(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000" ascii
    $s2 = "eturn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3 = "nction f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s4 = "000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\"" ascii
    $s5 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}