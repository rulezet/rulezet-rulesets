rule TTP_XOR_QUAD_CurrentVersionRun_e14c {
  strings:
    $key_e14c = { b2 23 [2] 96 2d [2] bd 01 [2] 93 23 [2] 87 38 [2] 88 22 [2] 96 3f [2] 94 3e [2] 8f 38 [2] 93 3f [2] 8f 10 }

  condition:
    any of them
}