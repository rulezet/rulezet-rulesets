rule TTP_XOR_QUAD_CurrentVersionRun_e763 {
  strings:
    $key_e763 = { b4 0c [2] 90 02 [2] bb 2e [2] 95 0c [2] 81 17 [2] 8e 0d [2] 90 10 [2] 92 11 [2] 89 17 [2] 95 10 [2] 89 3f }

  condition:
    any of them
}