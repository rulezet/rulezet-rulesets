rule TTP_XOR_QUAD_CurrentVersionRun_32b0 {
  strings:
    $key_32b0 = { 61 df [2] 45 d1 [2] 6e fd [2] 40 df [2] 54 c4 [2] 5b de [2] 45 c3 [2] 47 c2 [2] 5c c4 [2] 40 c3 [2] 5c ec }

  condition:
    any of them
}