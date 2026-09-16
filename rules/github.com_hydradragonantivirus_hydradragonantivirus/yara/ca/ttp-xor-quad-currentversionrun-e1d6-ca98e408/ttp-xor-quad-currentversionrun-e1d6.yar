rule TTP_XOR_QUAD_CurrentVersionRun_e1d6 {
  strings:
    $key_e1d6 = { b2 b9 [2] 96 b7 [2] bd 9b [2] 93 b9 [2] 87 a2 [2] 88 b8 [2] 96 a5 [2] 94 a4 [2] 8f a2 [2] 93 a5 [2] 8f 8a }

  condition:
    any of them
}