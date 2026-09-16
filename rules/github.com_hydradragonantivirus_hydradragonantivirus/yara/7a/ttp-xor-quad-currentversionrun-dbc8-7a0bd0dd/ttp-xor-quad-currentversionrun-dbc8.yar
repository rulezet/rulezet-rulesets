rule TTP_XOR_QUAD_CurrentVersionRun_dbc8 {
  strings:
    $key_dbc8 = { 88 a7 [2] ac a9 [2] 87 85 [2] a9 a7 [2] bd bc [2] b2 a6 [2] ac bb [2] ae ba [2] b5 bc [2] a9 bb [2] b5 94 }

  condition:
    any of them
}