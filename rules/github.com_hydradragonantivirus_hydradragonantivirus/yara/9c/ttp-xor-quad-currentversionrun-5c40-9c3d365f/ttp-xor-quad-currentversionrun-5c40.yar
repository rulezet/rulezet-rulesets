rule TTP_XOR_QUAD_CurrentVersionRun_5c40 {
  strings:
    $key_5c40 = { 0f 2f [2] 2b 21 [2] 00 0d [2] 2e 2f [2] 3a 34 [2] 35 2e [2] 2b 33 [2] 29 32 [2] 32 34 [2] 2e 33 [2] 32 1c }

  condition:
    any of them
}