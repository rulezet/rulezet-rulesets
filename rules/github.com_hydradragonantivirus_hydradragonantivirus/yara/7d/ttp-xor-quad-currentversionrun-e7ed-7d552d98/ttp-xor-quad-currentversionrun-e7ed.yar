rule TTP_XOR_QUAD_CurrentVersionRun_e7ed {
  strings:
    $key_e7ed = { b4 82 [2] 90 8c [2] bb a0 [2] 95 82 [2] 81 99 [2] 8e 83 [2] 90 9e [2] 92 9f [2] 89 99 [2] 95 9e [2] 89 b1 }

  condition:
    any of them
}