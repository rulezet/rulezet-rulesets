rule TTP_XOR_QUAD_CurrentVersionRun_31f1 {
  strings:
    $key_31f1 = { 62 9e [2] 46 90 [2] 6d bc [2] 43 9e [2] 57 85 [2] 58 9f [2] 46 82 [2] 44 83 [2] 5f 85 [2] 43 82 [2] 5f ad }

  condition:
    any of them
}