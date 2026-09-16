rule TTP_XOR_QUAD_CurrentVersionRun_f5f1 {
  strings:
    $key_f5f1 = { a6 9e [2] 82 90 [2] a9 bc [2] 87 9e [2] 93 85 [2] 9c 9f [2] 82 82 [2] 80 83 [2] 9b 85 [2] 87 82 [2] 9b ad }

  condition:
    any of them
}