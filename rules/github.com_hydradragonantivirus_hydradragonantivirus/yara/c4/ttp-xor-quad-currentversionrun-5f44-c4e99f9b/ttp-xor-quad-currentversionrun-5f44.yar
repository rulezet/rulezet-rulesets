rule TTP_XOR_QUAD_CurrentVersionRun_5f44 {
  strings:
    $key_5f44 = { 0c 2b [2] 28 25 [2] 03 09 [2] 2d 2b [2] 39 30 [2] 36 2a [2] 28 37 [2] 2a 36 [2] 31 30 [2] 2d 37 [2] 31 18 }

  condition:
    any of them
}