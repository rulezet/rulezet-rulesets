rule TTP_XOR_QUAD_CurrentVersionRun_5ac5 {
  strings:
    $key_5ac5 = { 09 aa [2] 2d a4 [2] 06 88 [2] 28 aa [2] 3c b1 [2] 33 ab [2] 2d b6 [2] 2f b7 [2] 34 b1 [2] 28 b6 [2] 34 99 }

  condition:
    any of them
}