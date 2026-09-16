rule TTP_XOR_QUAD_CurrentVersionRun_5fc5 {
  strings:
    $key_5fc5 = { 0c aa [2] 28 a4 [2] 03 88 [2] 2d aa [2] 39 b1 [2] 36 ab [2] 28 b6 [2] 2a b7 [2] 31 b1 [2] 2d b6 [2] 31 99 }

  condition:
    any of them
}