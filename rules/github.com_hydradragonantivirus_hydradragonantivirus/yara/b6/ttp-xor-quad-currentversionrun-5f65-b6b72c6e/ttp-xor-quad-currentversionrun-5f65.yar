rule TTP_XOR_QUAD_CurrentVersionRun_5f65 {
  strings:
    $key_5f65 = { 0c 0a [2] 28 04 [2] 03 28 [2] 2d 0a [2] 39 11 [2] 36 0b [2] 28 16 [2] 2a 17 [2] 31 11 [2] 2d 16 [2] 31 39 }

  condition:
    any of them
}