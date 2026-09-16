rule TTP_XOR_QUAD_CurrentVersionRun_5f04 {
  strings:
    $key_5f04 = { 0c 6b [2] 28 65 [2] 03 49 [2] 2d 6b [2] 39 70 [2] 36 6a [2] 28 77 [2] 2a 76 [2] 31 70 [2] 2d 77 [2] 31 58 }

  condition:
    any of them
}