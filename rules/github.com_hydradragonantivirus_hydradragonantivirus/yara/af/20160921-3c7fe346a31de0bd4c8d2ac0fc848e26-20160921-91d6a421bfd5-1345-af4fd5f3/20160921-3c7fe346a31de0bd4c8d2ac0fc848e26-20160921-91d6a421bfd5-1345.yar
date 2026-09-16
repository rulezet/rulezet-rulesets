rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_1345 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash4       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1  = "KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s2  = "000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\"" ascii
    $s3  = "unction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){ret" ascii
    $s4  = "f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp" ascii
    $s5  = "nction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return" ascii
    $s6  = "(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii
    $s7  = "000(){return \"YTp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(func" ascii
    $s9  = "unction f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){retu" ascii
    $s10 = "n f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"" ascii
    $s11 = "(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s12 = "n \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s13 = "{return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s14 = "eturn \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s15 = "f000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}