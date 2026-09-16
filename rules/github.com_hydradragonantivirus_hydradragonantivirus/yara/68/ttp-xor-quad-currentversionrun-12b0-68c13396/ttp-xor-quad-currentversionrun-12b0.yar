rule TTP_XOR_QUAD_CurrentVersionRun_12b0 {
  strings:
    $key_12b0 = { 41 df [2] 65 d1 [2] 4e fd [2] 60 df [2] 74 c4 [2] 7b de [2] 65 c3 [2] 67 c2 [2] 7c c4 [2] 60 c3 [2] 7c ec }

  condition:
    any of them
}