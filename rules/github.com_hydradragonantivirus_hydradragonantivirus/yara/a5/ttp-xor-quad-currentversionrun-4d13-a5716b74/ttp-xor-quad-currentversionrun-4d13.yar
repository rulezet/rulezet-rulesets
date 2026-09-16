rule TTP_XOR_QUAD_CurrentVersionRun_4d13 {
  strings:
    $key_4d13 = { 1e 7c [2] 3a 72 [2] 11 5e [2] 3f 7c [2] 2b 67 [2] 24 7d [2] 3a 60 [2] 38 61 [2] 23 67 [2] 3f 60 [2] 23 4f }

  condition:
    any of them
}