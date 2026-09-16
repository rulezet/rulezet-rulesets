rule TTP_XOR_QUAD_CurrentVersionRun_37b0 {
  strings:
    $key_37b0 = { 64 df [2] 40 d1 [2] 6b fd [2] 45 df [2] 51 c4 [2] 5e de [2] 40 c3 [2] 42 c2 [2] 59 c4 [2] 45 c3 [2] 59 ec }

  condition:
    any of them
}