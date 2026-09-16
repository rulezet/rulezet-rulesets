rule TTP_XOR_QUAD_CurrentVersionRun_4d16 {
  strings:
    $key_4d16 = { 1e 79 [2] 3a 77 [2] 11 5b [2] 3f 79 [2] 2b 62 [2] 24 78 [2] 3a 65 [2] 38 64 [2] 23 62 [2] 3f 65 [2] 23 4a }

  condition:
    any of them
}