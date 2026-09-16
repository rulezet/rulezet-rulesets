rule TTP_XOR_QUAD_CurrentVersionRun_40f1 {
  strings:
    $key_40f1 = { 13 9e [2] 37 90 [2] 1c bc [2] 32 9e [2] 26 85 [2] 29 9f [2] 37 82 [2] 35 83 [2] 2e 85 [2] 32 82 [2] 2e ad }

  condition:
    any of them
}