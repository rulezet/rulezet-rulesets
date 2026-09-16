rule TTP_XOR_QUAD_CurrentVersionRun_e65f {
  strings:
    $key_e65f = { b5 30 [2] 91 3e [2] ba 12 [2] 94 30 [2] 80 2b [2] 8f 31 [2] 91 2c [2] 93 2d [2] 88 2b [2] 94 2c [2] 88 03 }

  condition:
    any of them
}