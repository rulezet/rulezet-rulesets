rule TTP_XOR_QUAD_CurrentVersionRun_4d19 {
  strings:
    $key_4d19 = { 1e 76 [2] 3a 78 [2] 11 54 [2] 3f 76 [2] 2b 6d [2] 24 77 [2] 3a 6a [2] 38 6b [2] 23 6d [2] 3f 6a [2] 23 45 }

  condition:
    any of them
}