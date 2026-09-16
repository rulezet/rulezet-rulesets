rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_c10352a0b5ce_1376 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1  = "turn \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()," ascii
    $s2  = ")(),(function f000(){return \"RLk\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii
    $s3  = " f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s4  = " f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s5  = "eturn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})()," ascii
    $s6  = " \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(func" ascii
    $s7  = "n \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s8  = "f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\"" ascii
    $s9  = "ion f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s10 = "(),(function f000(){return \"Oh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s11 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000()" ascii
    $s12 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(function f000(" ascii
    $s13 = "turn \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s14 = "urn \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}