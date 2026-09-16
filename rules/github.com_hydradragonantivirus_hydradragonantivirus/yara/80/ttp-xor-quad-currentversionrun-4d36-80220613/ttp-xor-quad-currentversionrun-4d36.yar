rule TTP_XOR_QUAD_CurrentVersionRun_4d36 {
  strings:
    $key_4d36 = { 1e 59 [2] 3a 57 [2] 11 7b [2] 3f 59 [2] 2b 42 [2] 24 58 [2] 3a 45 [2] 38 44 [2] 23 42 [2] 3f 45 [2] 23 6a }

  condition:
    any of them
}