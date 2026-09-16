rule TTP_XOR_QUAD_CurrentVersionRun_cad4 {
  strings:
    $key_cad4 = { 99 bb [2] bd b5 [2] 96 99 [2] b8 bb [2] ac a0 [2] a3 ba [2] bd a7 [2] bf a6 [2] a4 a0 [2] b8 a7 [2] a4 88 }

  condition:
    any of them
}