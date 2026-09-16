rule TTP_XOR_QUAD_CurrentVersionRun_6940 {
  strings:
    $key_6940 = { 3a 2f [2] 1e 21 [2] 35 0d [2] 1b 2f [2] 0f 34 [2] 00 2e [2] 1e 33 [2] 1c 32 [2] 07 34 [2] 1b 33 [2] 07 1c }

  condition:
    any of them
}