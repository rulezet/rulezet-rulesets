rule TTP_XOR_QUAD_CurrentVersionRun_4d40 {
  strings:
    $key_4d40 = { 1e 2f [2] 3a 21 [2] 11 0d [2] 3f 2f [2] 2b 34 [2] 24 2e [2] 3a 33 [2] 38 32 [2] 23 34 [2] 3f 33 [2] 23 1c }

  condition:
    any of them
}