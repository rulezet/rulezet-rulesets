rule _20160921_b86272ed73cef9077c204056df823014_20160921_cae1392fd0c6_5655 {
  meta:
    description = "datamaliciousorder - from files 20160921_b86272ed73cef9077c204056df823014.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s2 = "function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){re" ascii
    $s3 = "urn \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s4 = "f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"M" ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}