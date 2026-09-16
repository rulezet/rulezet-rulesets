rule TTP_XOR_QUAD_CurrentVersionRun_e6c8 {
  strings:
    $key_e6c8 = { b5 a7 [2] 91 a9 [2] ba 85 [2] 94 a7 [2] 80 bc [2] 8f a6 [2] 91 bb [2] 93 ba [2] 88 bc [2] 94 bb [2] 88 94 }

  condition:
    any of them
}