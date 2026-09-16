rule TTP_XOR_QUAD_CurrentVersionRun_e1c7 {
  strings:
    $key_e1c7 = { b2 a8 [2] 96 a6 [2] bd 8a [2] 93 a8 [2] 87 b3 [2] 88 a9 [2] 96 b4 [2] 94 b5 [2] 8f b3 [2] 93 b4 [2] 8f 9b }

  condition:
    any of them
}