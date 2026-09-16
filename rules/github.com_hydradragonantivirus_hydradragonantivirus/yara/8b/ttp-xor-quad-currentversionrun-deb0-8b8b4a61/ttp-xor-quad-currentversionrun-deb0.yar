rule TTP_XOR_QUAD_CurrentVersionRun_deb0 {
  strings:
    $key_deb0 = { 8d df [2] a9 d1 [2] 82 fd [2] ac df [2] b8 c4 [2] b7 de [2] a9 c3 [2] ab c2 [2] b0 c4 [2] ac c3 [2] b0 ec }

  condition:
    any of them
}