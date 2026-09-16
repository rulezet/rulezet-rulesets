rule TTP_XOR_QUAD_CurrentVersionRun_4d1a {
  strings:
    $key_4d1a = { 1e 75 [2] 3a 7b [2] 11 57 [2] 3f 75 [2] 2b 6e [2] 24 74 [2] 3a 69 [2] 38 68 [2] 23 6e [2] 3f 69 [2] 23 46 }

  condition:
    any of them
}