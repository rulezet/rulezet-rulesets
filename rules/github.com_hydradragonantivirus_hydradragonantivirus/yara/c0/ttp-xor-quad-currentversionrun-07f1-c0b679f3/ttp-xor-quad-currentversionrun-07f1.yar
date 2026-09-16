rule TTP_XOR_QUAD_CurrentVersionRun_07f1 {
  strings:
    $key_07f1 = { 54 9e [2] 70 90 [2] 5b bc [2] 75 9e [2] 61 85 [2] 6e 9f [2] 70 82 [2] 72 83 [2] 69 85 [2] 75 82 [2] 69 ad }

  condition:
    any of them
}