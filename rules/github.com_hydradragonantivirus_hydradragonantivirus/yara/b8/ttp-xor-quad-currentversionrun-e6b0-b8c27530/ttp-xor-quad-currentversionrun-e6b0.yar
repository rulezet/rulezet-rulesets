rule TTP_XOR_QUAD_CurrentVersionRun_e6b0 {
  strings:
    $key_e6b0 = { b5 df [2] 91 d1 [2] ba fd [2] 94 df [2] 80 c4 [2] 8f de [2] 91 c3 [2] 93 c2 [2] 88 c4 [2] 94 c3 [2] 88 ec }

  condition:
    any of them
}