rule TTP_XOR_QUAD_CurrentVersionRun_fa43 {
  strings:
    $key_fa43 = { a9 2c [2] 8d 22 [2] a6 0e [2] 88 2c [2] 9c 37 [2] 93 2d [2] 8d 30 [2] 8f 31 [2] 94 37 [2] 88 30 [2] 94 1f }

  condition:
    any of them
}