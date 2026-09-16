rule TTP_XOR_QUAD_CurrentVersionRun_e152 {
  strings:
    $key_e152 = { b2 3d [2] 96 33 [2] bd 1f [2] 93 3d [2] 87 26 [2] 88 3c [2] 96 21 [2] 94 20 [2] 8f 26 [2] 93 21 [2] 8f 0e }

  condition:
    any of them
}