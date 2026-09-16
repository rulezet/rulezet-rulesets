rule TTP_XOR_QUAD_CurrentVersionRun_47f1 {
  strings:
    $key_47f1 = { 14 9e [2] 30 90 [2] 1b bc [2] 35 9e [2] 21 85 [2] 2e 9f [2] 30 82 [2] 32 83 [2] 29 85 [2] 35 82 [2] 29 ad }

  condition:
    any of them
}