rule TTP_XOR_QUAD_CurrentVersionRun_e1c6 {
  strings:
    $key_e1c6 = { b2 a9 [2] 96 a7 [2] bd 8b [2] 93 a9 [2] 87 b2 [2] 88 a8 [2] 96 b5 [2] 94 b4 [2] 8f b2 [2] 93 b5 [2] 8f 9a }

  condition:
    any of them
}