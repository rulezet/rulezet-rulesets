rule TTP_XOR_QUAD_CurrentVersionRun_e75e {
  strings:
    $key_e75e = { b4 31 [2] 90 3f [2] bb 13 [2] 95 31 [2] 81 2a [2] 8e 30 [2] 90 2d [2] 92 2c [2] 89 2a [2] 95 2d [2] 89 02 }

  condition:
    any of them
}