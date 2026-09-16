rule TTP_XOR_QUAD_CurrentVersionRun_67f1 {
  strings:
    $key_67f1 = { 34 9e [2] 10 90 [2] 3b bc [2] 15 9e [2] 01 85 [2] 0e 9f [2] 10 82 [2] 12 83 [2] 09 85 [2] 15 82 [2] 09 ad }

  condition:
    any of them
}