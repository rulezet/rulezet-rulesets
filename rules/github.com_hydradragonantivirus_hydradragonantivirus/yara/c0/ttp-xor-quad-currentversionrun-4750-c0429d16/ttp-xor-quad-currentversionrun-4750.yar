rule TTP_XOR_QUAD_CurrentVersionRun_4750 {
  strings:
    $key_4750 = { 14 3f [2] 30 31 [2] 1b 1d [2] 35 3f [2] 21 24 [2] 2e 3e [2] 30 23 [2] 32 22 [2] 29 24 [2] 35 23 [2] 29 0c }

  condition:
    any of them
}