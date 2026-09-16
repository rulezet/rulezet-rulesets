rule TTP_XOR_QUAD_CurrentVersionRun_4458 {
  strings:
    $key_4458 = { 17 37 [2] 33 39 [2] 18 15 [2] 36 37 [2] 22 2c [2] 2d 36 [2] 33 2b [2] 31 2a [2] 2a 2c [2] 36 2b [2] 2a 04 }

  condition:
    any of them
}