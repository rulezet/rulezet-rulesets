rule TTP_XOR_QUAD_CurrentVersionRun_30b0 {
  strings:
    $key_30b0 = { 63 df [2] 47 d1 [2] 6c fd [2] 42 df [2] 56 c4 [2] 59 de [2] 47 c3 [2] 45 c2 [2] 5e c4 [2] 42 c3 [2] 5e ec }

  condition:
    any of them
}