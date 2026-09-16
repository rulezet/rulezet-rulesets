rule TTP_XOR_QUAD_CurrentVersionRun_e15e {
  strings:
    $key_e15e = { b2 31 [2] 96 3f [2] bd 13 [2] 93 31 [2] 87 2a [2] 88 30 [2] 96 2d [2] 94 2c [2] 8f 2a [2] 93 2d [2] 8f 02 }

  condition:
    any of them
}