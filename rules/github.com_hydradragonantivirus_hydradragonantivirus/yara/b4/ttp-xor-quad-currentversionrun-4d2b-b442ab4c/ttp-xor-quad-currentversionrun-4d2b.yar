rule TTP_XOR_QUAD_CurrentVersionRun_4d2b {
  strings:
    $key_4d2b = { 1e 44 [2] 3a 4a [2] 11 66 [2] 3f 44 [2] 2b 5f [2] 24 45 [2] 3a 58 [2] 38 59 [2] 23 5f [2] 3f 58 [2] 23 77 }

  condition:
    any of them
}