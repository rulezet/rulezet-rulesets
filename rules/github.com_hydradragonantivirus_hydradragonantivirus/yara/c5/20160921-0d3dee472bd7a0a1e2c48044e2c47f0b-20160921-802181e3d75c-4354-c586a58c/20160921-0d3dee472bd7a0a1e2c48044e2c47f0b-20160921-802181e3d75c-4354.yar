rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_802181e3d75c_4354 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1 = "),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){" ascii
    $s2 = ";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s3 = "(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";" ascii
    $s4 = " \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(funct" ascii
    $s5 = "on f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}