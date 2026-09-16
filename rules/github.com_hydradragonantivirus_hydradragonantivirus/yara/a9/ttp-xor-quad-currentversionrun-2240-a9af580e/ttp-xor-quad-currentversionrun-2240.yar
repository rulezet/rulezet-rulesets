rule TTP_XOR_QUAD_CurrentVersionRun_2240 {
  strings:
    $key_2240 = { 71 2f [2] 55 21 [2] 7e 0d [2] 50 2f [2] 44 34 [2] 4b 2e [2] 55 33 [2] 57 32 [2] 4c 34 [2] 50 33 [2] 4c 1c }

  condition:
    any of them
}