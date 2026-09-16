rule TTP_XOR_QUAD_CurrentVersionRun_41d9 {
  strings:
    $key_41d9 = { 12 b6 [2] 36 b8 [2] 1d 94 [2] 33 b6 [2] 27 ad [2] 28 b7 [2] 36 aa [2] 34 ab [2] 2f ad [2] 33 aa [2] 2f 85 }

  condition:
    any of them
}