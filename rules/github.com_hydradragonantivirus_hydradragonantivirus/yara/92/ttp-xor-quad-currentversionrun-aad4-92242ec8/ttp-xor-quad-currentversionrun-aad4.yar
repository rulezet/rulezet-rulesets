rule TTP_XOR_QUAD_CurrentVersionRun_aad4 {
  strings:
    $key_aad4 = { f9 bb [2] dd b5 [2] f6 99 [2] d8 bb [2] cc a0 [2] c3 ba [2] dd a7 [2] df a6 [2] c4 a0 [2] d8 a7 [2] c4 88 }

  condition:
    any of them
}