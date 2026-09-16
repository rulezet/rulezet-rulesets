rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_0d3dee472bd7_366 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"

  strings:
    $s1  = "unction f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2  = "),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s3  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s4  = "Xg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s5  = "turn \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s6  = "f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s7  = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";" ascii
    $s8  = "turn \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})()," ascii
    $s9  = " f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s10 = ",(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){" ascii
    $s11 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s12 = "Pt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s13 = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Z" ascii
    $s14 = " \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s15 = "f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s16 = "on f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s17 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s18 = "),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s19 = "\"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s20 = "){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}