rule TTP_XOR_QUAD_CurrentVersionRun_e774 {
  strings:
    $key_e774 = { b4 1b [2] 90 15 [2] bb 39 [2] 95 1b [2] 81 00 [2] 8e 1a [2] 90 07 [2] 92 06 [2] 89 00 [2] 95 07 [2] 89 28 }

  condition:
    any of them
}