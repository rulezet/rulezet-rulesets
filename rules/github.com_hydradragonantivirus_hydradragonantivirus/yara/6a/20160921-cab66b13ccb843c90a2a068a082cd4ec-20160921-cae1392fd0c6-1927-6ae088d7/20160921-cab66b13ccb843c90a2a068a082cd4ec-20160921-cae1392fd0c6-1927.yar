rule _20160921_cab66b13ccb843c90a2a068a082cd4ec_20160921_cae1392fd0c6_1927 {
  meta:
    description = "datamaliciousorder - from files 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1  = "ion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s2  = "urn \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(f" ascii
    $s3  = "nction f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s4  = "n f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Z" ascii
    $s5  = "ction f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retur" ascii
    $s6  = "turn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})()," ascii
    $s7  = "turn \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(" ascii
    $s8  = "})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f00" ascii
    $s9  = "on f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s10 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}