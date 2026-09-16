rule TTP_XOR_QUAD_CurrentVersionRun_56f1 {
  strings:
    $key_56f1 = { 05 9e [2] 21 90 [2] 0a bc [2] 24 9e [2] 30 85 [2] 3f 9f [2] 21 82 [2] 23 83 [2] 38 85 [2] 24 82 [2] 38 ad }

  condition:
    any of them
}