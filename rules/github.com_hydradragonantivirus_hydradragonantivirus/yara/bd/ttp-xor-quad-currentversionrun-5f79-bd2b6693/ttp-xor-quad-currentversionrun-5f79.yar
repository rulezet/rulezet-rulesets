rule TTP_XOR_QUAD_CurrentVersionRun_5f79 {
  strings:
    $key_5f79 = { 0c 16 [2] 28 18 [2] 03 34 [2] 2d 16 [2] 39 0d [2] 36 17 [2] 28 0a [2] 2a 0b [2] 31 0d [2] 2d 0a [2] 31 25 }

  condition:
    any of them
}