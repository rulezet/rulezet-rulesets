rule TTP_XOR_QUAD_CurrentVersionRun_255b {
  strings:
    $key_255b = { 76 34 [2] 52 3a [2] 79 16 [2] 57 34 [2] 43 2f [2] 4c 35 [2] 52 28 [2] 50 29 [2] 4b 2f [2] 57 28 [2] 4b 07 }

  condition:
    any of them
}