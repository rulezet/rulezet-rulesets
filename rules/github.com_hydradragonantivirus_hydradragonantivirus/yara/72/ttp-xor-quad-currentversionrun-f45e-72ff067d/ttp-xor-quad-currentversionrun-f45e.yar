rule TTP_XOR_QUAD_CurrentVersionRun_f45e {
  strings:
    $key_f45e = { a7 31 [2] 83 3f [2] a8 13 [2] 86 31 [2] 92 2a [2] 9d 30 [2] 83 2d [2] 81 2c [2] 9a 2a [2] 86 2d [2] 9a 02 }

  condition:
    any of them
}