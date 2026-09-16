rule TTP_XOR_QUAD_CurrentVersionRun_e715 {
  strings:
    $key_e715 = { b4 7a [2] 90 74 [2] bb 58 [2] 95 7a [2] 81 61 [2] 8e 7b [2] 90 66 [2] 92 67 [2] 89 61 [2] 95 66 [2] 89 49 }

  condition:
    any of them
}