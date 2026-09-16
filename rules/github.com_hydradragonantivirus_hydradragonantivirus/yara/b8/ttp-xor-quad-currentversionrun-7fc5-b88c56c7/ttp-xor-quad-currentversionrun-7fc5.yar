rule TTP_XOR_QUAD_CurrentVersionRun_7fc5 {
  strings:
    $key_7fc5 = { 2c aa [2] 08 a4 [2] 23 88 [2] 0d aa [2] 19 b1 [2] 16 ab [2] 08 b6 [2] 0a b7 [2] 11 b1 [2] 0d b6 [2] 11 99 }

  condition:
    any of them
}