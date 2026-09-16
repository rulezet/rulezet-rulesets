rule TTP_XOR_QUAD_CurrentVersionRun_e707 {
  strings:
    $key_e707 = { b4 68 [2] 90 66 [2] bb 4a [2] 95 68 [2] 81 73 [2] 8e 69 [2] 90 74 [2] 92 75 [2] 89 73 [2] 95 74 [2] 89 5b }

  condition:
    any of them
}