rule TTP_XOR_QUAD_CurrentVersionRun_5f6b {
  strings:
    $key_5f6b = { 0c 04 [2] 28 0a [2] 03 26 [2] 2d 04 [2] 39 1f [2] 36 05 [2] 28 18 [2] 2a 19 [2] 31 1f [2] 2d 18 [2] 31 37 }

  condition:
    any of them
}