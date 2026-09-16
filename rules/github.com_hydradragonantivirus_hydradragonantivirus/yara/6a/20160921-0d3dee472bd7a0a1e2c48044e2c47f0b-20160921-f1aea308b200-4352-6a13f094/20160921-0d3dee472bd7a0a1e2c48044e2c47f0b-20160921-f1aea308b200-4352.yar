rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_f1aea308b200_4352 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii
    $s2 = "n f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii
    $s3 = "rn \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"" ascii
    $s5 = "){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}