rule TTP_XOR_QUAD_CurrentVersionRun_eec5 {
  strings:
    $key_eec5 = { bd aa [2] 99 a4 [2] b2 88 [2] 9c aa [2] 88 b1 [2] 87 ab [2] 99 b6 [2] 9b b7 [2] 80 b1 [2] 9c b6 [2] 80 99 }

  condition:
    any of them
}