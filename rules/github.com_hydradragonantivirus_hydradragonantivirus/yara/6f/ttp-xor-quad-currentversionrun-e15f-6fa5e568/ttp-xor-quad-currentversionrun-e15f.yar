rule TTP_XOR_QUAD_CurrentVersionRun_e15f {
  strings:
    $key_e15f = { b2 30 [2] 96 3e [2] bd 12 [2] 93 30 [2] 87 2b [2] 88 31 [2] 96 2c [2] 94 2d [2] 8f 2b [2] 93 2c [2] 8f 03 }

  condition:
    any of them
}