rule TTP_XOR_QUAD_CurrentVersionRun_41f1 {
  strings:
    $key_41f1 = { 12 9e [2] 36 90 [2] 1d bc [2] 33 9e [2] 27 85 [2] 28 9f [2] 36 82 [2] 34 83 [2] 2f 85 [2] 33 82 [2] 2f ad }

  condition:
    any of them
}