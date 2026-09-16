rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_1c5a439961f0_4455 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_1c5a439961f0eccee5312fdbb892fb0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"

  strings:
    $s1 = "tion f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return " ascii
    $s2 = "rn \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s3 = "(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function " ascii
    $s5 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}