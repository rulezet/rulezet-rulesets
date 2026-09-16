rule TTP_XOR_QUAD_CurrentVersionRun_b5c9 {
  strings:
    $key_b5c9 = { e6 a6 [2] c2 a8 [2] e9 84 [2] c7 a6 [2] d3 bd [2] dc a7 [2] c2 ba [2] c0 bb [2] db bd [2] c7 ba [2] db 95 }

  condition:
    any of them
}