rule TTP_XOR_QUAD_CurrentVersionRun_e759 {
  strings:
    $key_e759 = { b4 36 [2] 90 38 [2] bb 14 [2] 95 36 [2] 81 2d [2] 8e 37 [2] 90 2a [2] 92 2b [2] 89 2d [2] 95 2a [2] 89 05 }

  condition:
    any of them
}