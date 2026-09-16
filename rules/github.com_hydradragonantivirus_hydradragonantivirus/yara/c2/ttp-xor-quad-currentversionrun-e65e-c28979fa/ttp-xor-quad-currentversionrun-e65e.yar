rule TTP_XOR_QUAD_CurrentVersionRun_e65e {
  strings:
    $key_e65e = { b5 31 [2] 91 3f [2] ba 13 [2] 94 31 [2] 80 2a [2] 8f 30 [2] 91 2d [2] 93 2c [2] 88 2a [2] 94 2d [2] 88 02 }

  condition:
    any of them
}