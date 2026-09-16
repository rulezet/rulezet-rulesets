rule TTP_XOR_QUAD_CurrentVersionRun_10f1 {
  strings:
    $key_10f1 = { 43 9e [2] 67 90 [2] 4c bc [2] 62 9e [2] 76 85 [2] 79 9f [2] 67 82 [2] 65 83 [2] 7e 85 [2] 62 82 [2] 7e ad }

  condition:
    any of them
}