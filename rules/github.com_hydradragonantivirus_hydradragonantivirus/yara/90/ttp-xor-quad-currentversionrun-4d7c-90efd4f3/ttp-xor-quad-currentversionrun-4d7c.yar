rule TTP_XOR_QUAD_CurrentVersionRun_4d7c {
  strings:
    $key_4d7c = { 1e 13 [2] 3a 1d [2] 11 31 [2] 3f 13 [2] 2b 08 [2] 24 12 [2] 3a 0f [2] 38 0e [2] 23 08 [2] 3f 0f [2] 23 20 }

  condition:
    any of them
}