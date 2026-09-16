rule _20160921_50ddf5c101f65dbae1a99b5967b69eaf_20160921_6d45b48d2143_5163 {
  meta:
    description = "datamaliciousorder - from files 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash2       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"

  strings:
    $s1 = "rn \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s2 = "n \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s3 = "turn \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s4 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f0" ascii
    $s5 = "){return \"Mc\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}