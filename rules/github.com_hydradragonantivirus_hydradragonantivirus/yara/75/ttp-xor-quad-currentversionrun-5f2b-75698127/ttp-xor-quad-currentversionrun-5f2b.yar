rule TTP_XOR_QUAD_CurrentVersionRun_5f2b {
  strings:
    $key_5f2b = { 0c 44 [2] 28 4a [2] 03 66 [2] 2d 44 [2] 39 5f [2] 36 45 [2] 28 58 [2] 2a 59 [2] 31 5f [2] 2d 58 [2] 31 77 }

  condition:
    any of them
}