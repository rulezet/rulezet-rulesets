rule TTP_XOR_QUAD_CurrentVersionRun_36f1 {
  strings:
    $key_36f1 = { 65 9e [2] 41 90 [2] 6a bc [2] 44 9e [2] 50 85 [2] 5f 9f [2] 41 82 [2] 43 83 [2] 58 85 [2] 44 82 [2] 58 ad }

  condition:
    any of them
}