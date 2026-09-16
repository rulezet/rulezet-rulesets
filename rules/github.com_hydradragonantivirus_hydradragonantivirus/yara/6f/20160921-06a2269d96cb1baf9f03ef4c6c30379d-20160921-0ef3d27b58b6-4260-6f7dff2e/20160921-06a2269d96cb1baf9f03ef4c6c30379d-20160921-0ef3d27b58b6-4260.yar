rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4260 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash4       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "rn \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s2 = "return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s3 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s4 = "rn \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s5 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}