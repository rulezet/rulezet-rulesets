rule TTP_XOR_QUAD_CurrentVersionRun_6ec5 {
  strings:
    $key_6ec5 = { 3d aa [2] 19 a4 [2] 32 88 [2] 1c aa [2] 08 b1 [2] 07 ab [2] 19 b6 [2] 1b b7 [2] 00 b1 [2] 1c b6 [2] 00 99 }

  condition:
    any of them
}