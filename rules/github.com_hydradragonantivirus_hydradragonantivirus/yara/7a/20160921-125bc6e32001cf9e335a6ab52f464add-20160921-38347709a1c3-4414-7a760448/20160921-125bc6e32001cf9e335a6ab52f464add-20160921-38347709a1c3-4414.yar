rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_38347709a1c3_4414 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash3       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"

  strings:
    $s1 = "unction fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){ret" ascii
    $s2 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"" ascii
    $s3 = " \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "g\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function" ascii
    $s5 = "{return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}