rule _20160921_11c4976357ef8a651d058575507518ca_20160921_203e0165d7eb_2709 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_203e0165d7eb1b32389bd0efd4bc9546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"

  strings:
    $s1 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s2 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(fun" ascii
    $s3 = ")(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(functi" ascii
    $s5 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s6 = "u\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s7 = "unction fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}