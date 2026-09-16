rule TTP_XOR_QUAD_CurrentVersionRun_b7ed {
  strings:
    $key_b7ed = { e4 82 [2] c0 8c [2] eb a0 [2] c5 82 [2] d1 99 [2] de 83 [2] c0 9e [2] c2 9f [2] d9 99 [2] c5 9e [2] d9 b1 }

  condition:
    any of them
}