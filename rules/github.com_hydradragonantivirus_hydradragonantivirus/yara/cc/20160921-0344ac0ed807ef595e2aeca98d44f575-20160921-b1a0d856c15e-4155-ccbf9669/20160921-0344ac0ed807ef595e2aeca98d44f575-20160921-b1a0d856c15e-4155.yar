rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_b1a0d856c15e_4155 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = "turn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s2 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s3 = "(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";}" ascii
    $s4 = "n \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s5 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}