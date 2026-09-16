rule TTP_XOR_QUAD_CurrentVersionRun_e643 {
  strings:
    $key_e643 = { b5 2c [2] 91 22 [2] ba 0e [2] 94 2c [2] 80 37 [2] 8f 2d [2] 91 30 [2] 93 31 [2] 88 37 [2] 94 30 [2] 88 1f }

  condition:
    any of them
}