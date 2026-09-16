rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_bcf391146213_5242 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1 = "on f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s2 = "n f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"" ascii
    $s3 = "return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})()" ascii
    $s4 = "n \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(fu" ascii
    $s5 = "return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Mc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}