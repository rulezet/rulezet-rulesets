rule TTP_XOR_QUAD_CurrentVersionRun_5f78 {
  strings:
    $key_5f78 = { 0c 17 [2] 28 19 [2] 03 35 [2] 2d 17 [2] 39 0c [2] 36 16 [2] 28 0b [2] 2a 0a [2] 31 0c [2] 2d 0b [2] 31 24 }

  condition:
    any of them
}