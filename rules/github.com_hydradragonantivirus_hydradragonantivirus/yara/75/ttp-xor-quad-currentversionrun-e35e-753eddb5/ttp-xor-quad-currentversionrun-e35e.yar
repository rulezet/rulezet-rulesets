rule TTP_XOR_QUAD_CurrentVersionRun_e35e {
  strings:
    $key_e35e = { b0 31 [2] 94 3f [2] bf 13 [2] 91 31 [2] 85 2a [2] 8a 30 [2] 94 2d [2] 96 2c [2] 8d 2a [2] 91 2d [2] 8d 02 }

  condition:
    any of them
}