rule TTP_XOR_QUAD_CurrentVersionRun_4740 {
  strings:
    $key_4740 = { 14 2f [2] 30 21 [2] 1b 0d [2] 35 2f [2] 21 34 [2] 2e 2e [2] 30 33 [2] 32 32 [2] 29 34 [2] 35 33 [2] 29 1c }

  condition:
    any of them
}