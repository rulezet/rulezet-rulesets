rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_70a7f7f0df4f_4376 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash3       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})()" ascii
    $s2 = "eturn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})()," ascii
    $s3 = "00(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg" ascii
    $s4 = "on f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}