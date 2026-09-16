rule TTP_XOR_QUAD_CurrentVersionRun_1b5b {
  strings:
    $key_1b5b = { 48 34 [2] 6c 3a [2] 47 16 [2] 69 34 [2] 7d 2f [2] 72 35 [2] 6c 28 [2] 6e 29 [2] 75 2f [2] 69 28 [2] 75 07 }

  condition:
    any of them
}