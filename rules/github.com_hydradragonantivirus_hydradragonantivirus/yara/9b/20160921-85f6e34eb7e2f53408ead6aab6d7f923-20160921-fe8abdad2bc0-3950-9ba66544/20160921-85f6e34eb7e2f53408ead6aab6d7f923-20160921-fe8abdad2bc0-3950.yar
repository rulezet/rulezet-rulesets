rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_fe8abdad2bc0_3950 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "n f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s2 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy" ascii
    $s3 = "turn \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s4 = "0(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl" ascii
    $s5 = "0(){return \"RLk\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\"" ascii
    $s6 = "\"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}