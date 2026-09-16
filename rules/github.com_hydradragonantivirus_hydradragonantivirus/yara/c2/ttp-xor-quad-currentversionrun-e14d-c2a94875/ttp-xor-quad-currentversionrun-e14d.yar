rule TTP_XOR_QUAD_CurrentVersionRun_e14d {
  strings:
    $key_e14d = { b2 22 [2] 96 2c [2] bd 00 [2] 93 22 [2] 87 39 [2] 88 23 [2] 96 3e [2] 94 3f [2] 8f 39 [2] 93 3e [2] 8f 11 }

  condition:
    any of them
}