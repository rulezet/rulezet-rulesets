rule TTP_XOR_QUAD_CurrentVersionRun_1fc5 {
  strings:
    $key_1fc5 = { 4c aa [2] 68 a4 [2] 43 88 [2] 6d aa [2] 79 b1 [2] 76 ab [2] 68 b6 [2] 6a b7 [2] 71 b1 [2] 6d b6 [2] 71 99 }

  condition:
    any of them
}