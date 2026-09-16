rule TTP_XOR_QUAD_CurrentVersionRun_25ed {
  strings:
    $key_25ed = { 76 82 [2] 52 8c [2] 79 a0 [2] 57 82 [2] 43 99 [2] 4c 83 [2] 52 9e [2] 50 9f [2] 4b 99 [2] 57 9e [2] 4b b1 }

  condition:
    any of them
}