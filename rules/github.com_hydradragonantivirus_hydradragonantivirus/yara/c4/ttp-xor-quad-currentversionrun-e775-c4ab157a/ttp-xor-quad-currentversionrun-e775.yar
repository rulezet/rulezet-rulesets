rule TTP_XOR_QUAD_CurrentVersionRun_e775 {
  strings:
    $key_e775 = { b4 1a [2] 90 14 [2] bb 38 [2] 95 1a [2] 81 01 [2] 8e 1b [2] 90 06 [2] 92 07 [2] 89 01 [2] 95 06 [2] 89 29 }

  condition:
    any of them
}