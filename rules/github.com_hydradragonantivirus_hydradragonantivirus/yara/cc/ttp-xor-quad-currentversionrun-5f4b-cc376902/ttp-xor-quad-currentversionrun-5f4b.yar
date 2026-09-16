rule TTP_XOR_QUAD_CurrentVersionRun_5f4b {
  strings:
    $key_5f4b = { 0c 24 [2] 28 2a [2] 03 06 [2] 2d 24 [2] 39 3f [2] 36 25 [2] 28 38 [2] 2a 39 [2] 31 3f [2] 2d 38 [2] 31 17 }

  condition:
    any of them
}