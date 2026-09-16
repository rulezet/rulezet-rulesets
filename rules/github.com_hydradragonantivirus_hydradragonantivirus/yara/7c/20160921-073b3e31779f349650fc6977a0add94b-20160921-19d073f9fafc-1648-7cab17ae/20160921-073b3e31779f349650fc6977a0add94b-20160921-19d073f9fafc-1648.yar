rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_19d073f9fafc_1648 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"

  strings:
    $s1  = "rn \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s2  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){" ascii
    $s3  = "return \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4  = "){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})" ascii
    $s5  = " \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(functi" ascii
    $s6  = "unction f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){retur" ascii
    $s7  = "eturn \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(" ascii
    $s8  = "tion f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s9  = ")(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s10 = "00(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\"" ascii
    $s11 = "){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}