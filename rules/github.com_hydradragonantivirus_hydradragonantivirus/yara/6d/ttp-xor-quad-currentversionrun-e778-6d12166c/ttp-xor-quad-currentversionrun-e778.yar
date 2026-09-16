rule TTP_XOR_QUAD_CurrentVersionRun_e778 {
  strings:
    $key_e778 = { b4 17 [2] 90 19 [2] bb 35 [2] 95 17 [2] 81 0c [2] 8e 16 [2] 90 0b [2] 92 0a [2] 89 0c [2] 95 0b [2] 89 24 }

  condition:
    any of them
}