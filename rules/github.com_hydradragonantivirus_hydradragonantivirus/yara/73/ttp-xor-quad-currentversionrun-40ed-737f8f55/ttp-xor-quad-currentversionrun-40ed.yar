rule TTP_XOR_QUAD_CurrentVersionRun_40ed {
  strings:
    $key_40ed = { 13 82 [2] 37 8c [2] 1c a0 [2] 32 82 [2] 26 99 [2] 29 83 [2] 37 9e [2] 35 9f [2] 2e 99 [2] 32 9e [2] 2e b1 }

  condition:
    any of them
}