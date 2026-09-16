rule TTP_XOR_QUAD_CurrentVersionRun_4d4b {
  strings:
    $key_4d4b = { 1e 24 [2] 3a 2a [2] 11 06 [2] 3f 24 [2] 2b 3f [2] 24 25 [2] 3a 38 [2] 38 39 [2] 23 3f [2] 3f 38 [2] 23 17 }

  condition:
    any of them
}