rule TTP_XOR_QUAD_CurrentVersionRun_5c50 {
  strings:
    $key_5c50 = { 0f 3f [2] 2b 31 [2] 00 1d [2] 2e 3f [2] 3a 24 [2] 35 3e [2] 2b 23 [2] 29 22 [2] 32 24 [2] 2e 23 [2] 32 0c }

  condition:
    any of them
}