rule _20160921_9dc96613aa4c64f92e4ff218607f50d0_20160921_f7fa978ba93c_5589 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dc96613aa4c64f92e4ff218607f50d0.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "uck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UO" ascii
    $s2 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s3 = "rn \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s4 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s5 = "turn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}