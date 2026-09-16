rule TTP_XOR_QUAD_CurrentVersionRun_5f56 {
  strings:
    $key_5f56 = { 0c 39 [2] 28 37 [2] 03 1b [2] 2d 39 [2] 39 22 [2] 36 38 [2] 28 25 [2] 2a 24 [2] 31 22 [2] 2d 25 [2] 31 0a }

  condition:
    any of them
}