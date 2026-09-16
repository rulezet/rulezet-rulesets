rule TTP_XOR_QUAD_CurrentVersionRun_e713 {
  strings:
    $key_e713 = { b4 7c [2] 90 72 [2] bb 5e [2] 95 7c [2] 81 67 [2] 8e 7d [2] 90 60 [2] 92 61 [2] 89 67 [2] 95 60 [2] 89 4f }

  condition:
    any of them
}