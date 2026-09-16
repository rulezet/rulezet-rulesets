rule TTP_XOR_QUAD_CurrentVersionRun_e1c9 {
  strings:
    $key_e1c9 = { b2 a6 [2] 96 a8 [2] bd 84 [2] 93 a6 [2] 87 bd [2] 88 a7 [2] 96 ba [2] 94 bb [2] 8f bd [2] 93 ba [2] 8f 95 }

  condition:
    any of them
}