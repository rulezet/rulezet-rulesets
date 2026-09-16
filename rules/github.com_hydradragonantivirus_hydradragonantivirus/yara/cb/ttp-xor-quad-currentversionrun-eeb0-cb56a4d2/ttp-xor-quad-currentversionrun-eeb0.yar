rule TTP_XOR_QUAD_CurrentVersionRun_eeb0 {
  strings:
    $key_eeb0 = { bd df [2] 99 d1 [2] b2 fd [2] 9c df [2] 88 c4 [2] 87 de [2] 99 c3 [2] 9b c2 [2] 80 c4 [2] 9c c3 [2] 80 ec }

  condition:
    any of them
}