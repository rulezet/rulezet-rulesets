rule TTP_XOR_QUAD_CurrentVersionRun_4e4b {
  strings:
    $key_4e4b = { 1d 24 [2] 39 2a [2] 12 06 [2] 3c 24 [2] 28 3f [2] 27 25 [2] 39 38 [2] 3b 39 [2] 20 3f [2] 3c 38 [2] 20 17 }

  condition:
    any of them
}