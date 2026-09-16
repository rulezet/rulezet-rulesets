rule TTP_XOR_QUAD_CurrentVersionRun_2a41 {
  strings:
    $key_2a41 = { 79 2e [2] 5d 20 [2] 76 0c [2] 58 2e [2] 4c 35 [2] 43 2f [2] 5d 32 [2] 5f 33 [2] 44 35 [2] 58 32 [2] 44 1d }

  condition:
    any of them
}