rule TTP_XOR_QUAD_CurrentVersionRun_4e5b {
  strings:
    $key_4e5b = { 1d 34 [2] 39 3a [2] 12 16 [2] 3c 34 [2] 28 2f [2] 27 35 [2] 39 28 [2] 3b 29 [2] 20 2f [2] 3c 28 [2] 20 07 }

  condition:
    any of them
}