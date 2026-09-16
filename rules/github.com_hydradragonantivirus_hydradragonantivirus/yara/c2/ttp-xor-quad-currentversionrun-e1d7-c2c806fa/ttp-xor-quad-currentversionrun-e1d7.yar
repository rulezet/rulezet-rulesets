rule TTP_XOR_QUAD_CurrentVersionRun_e1d7 {
  strings:
    $key_e1d7 = { b2 b8 [2] 96 b6 [2] bd 9a [2] 93 b8 [2] 87 a3 [2] 88 b9 [2] 96 a4 [2] 94 a5 [2] 8f a3 [2] 93 a4 [2] 8f 8b }

  condition:
    any of them
}