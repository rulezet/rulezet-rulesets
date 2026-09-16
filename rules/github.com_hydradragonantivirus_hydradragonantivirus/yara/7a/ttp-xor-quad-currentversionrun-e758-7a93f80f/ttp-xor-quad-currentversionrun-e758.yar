rule TTP_XOR_QUAD_CurrentVersionRun_e758 {
  strings:
    $key_e758 = { b4 37 [2] 90 39 [2] bb 15 [2] 95 37 [2] 81 2c [2] 8e 36 [2] 90 2b [2] 92 2a [2] 89 2c [2] 95 2b [2] 89 04 }

  condition:
    any of them
}