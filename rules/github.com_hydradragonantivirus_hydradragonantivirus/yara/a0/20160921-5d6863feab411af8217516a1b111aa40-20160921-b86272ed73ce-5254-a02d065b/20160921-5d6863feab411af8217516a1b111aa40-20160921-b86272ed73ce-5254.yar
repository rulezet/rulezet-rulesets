rule _20160921_5d6863feab411af8217516a1b111aa40_20160921_b86272ed73ce_5254 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "unction f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\"" ascii
    $s3 = "\"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(func" ascii
    $s4 = " \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s5 = "function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}