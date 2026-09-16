rule TTP_XOR_QUAD_CurrentVersionRun_4d4a {
  strings:
    $key_4d4a = { 1e 25 [2] 3a 2b [2] 11 07 [2] 3f 25 [2] 2b 3e [2] 24 24 [2] 3a 39 [2] 38 38 [2] 23 3e [2] 3f 39 [2] 23 16 }

  condition:
    any of them
}