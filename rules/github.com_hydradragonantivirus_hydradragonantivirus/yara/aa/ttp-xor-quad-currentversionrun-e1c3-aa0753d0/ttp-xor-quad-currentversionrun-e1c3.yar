rule TTP_XOR_QUAD_CurrentVersionRun_e1c3 {
  strings:
    $key_e1c3 = { b2 ac [2] 96 a2 [2] bd 8e [2] 93 ac [2] 87 b7 [2] 88 ad [2] 96 b0 [2] 94 b1 [2] 8f b7 [2] 93 b0 [2] 8f 9f }

  condition:
    any of them
}