rule TTP_XOR_QUAD_CurrentVersionRun_4762 {
  strings:
    $key_4762 = { 14 0d [2] 30 03 [2] 1b 2f [2] 35 0d [2] 21 16 [2] 2e 0c [2] 30 11 [2] 32 10 [2] 29 16 [2] 35 11 [2] 29 3e }

  condition:
    any of them
}