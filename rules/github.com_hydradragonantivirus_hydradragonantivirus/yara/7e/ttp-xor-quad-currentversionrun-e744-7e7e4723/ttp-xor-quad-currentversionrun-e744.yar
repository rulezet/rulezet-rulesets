rule TTP_XOR_QUAD_CurrentVersionRun_e744 {
  strings:
    $key_e744 = { b4 2b [2] 90 25 [2] bb 09 [2] 95 2b [2] 81 30 [2] 8e 2a [2] 90 37 [2] 92 36 [2] 89 30 [2] 95 37 [2] 89 18 }

  condition:
    any of them
}