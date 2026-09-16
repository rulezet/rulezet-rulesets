rule TTP_XOR_QUAD_CurrentVersionRun_ff43 {
  strings:
    $key_ff43 = { ac 2c [2] 88 22 [2] a3 0e [2] 8d 2c [2] 99 37 [2] 96 2d [2] 88 30 [2] 8a 31 [2] 91 37 [2] 8d 30 [2] 91 1f }

  condition:
    any of them
}