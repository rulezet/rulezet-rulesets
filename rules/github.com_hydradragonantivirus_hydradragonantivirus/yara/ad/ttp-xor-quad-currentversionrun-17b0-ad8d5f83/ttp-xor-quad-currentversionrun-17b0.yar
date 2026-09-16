rule TTP_XOR_QUAD_CurrentVersionRun_17b0 {
  strings:
    $key_17b0 = { 44 df [2] 60 d1 [2] 4b fd [2] 65 df [2] 71 c4 [2] 7e de [2] 60 c3 [2] 62 c2 [2] 79 c4 [2] 65 c3 [2] 79 ec }

  condition:
    any of them
}