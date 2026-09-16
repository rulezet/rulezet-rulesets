rule TTP_XOR_QUAD_CurrentVersionRun_0759 {
  strings:
    $key_0759 = { 54 36 [2] 70 38 [2] 5b 14 [2] 75 36 [2] 61 2d [2] 6e 37 [2] 70 2a [2] 72 2b [2] 69 2d [2] 75 2a [2] 69 05 }

  condition:
    any of them
}