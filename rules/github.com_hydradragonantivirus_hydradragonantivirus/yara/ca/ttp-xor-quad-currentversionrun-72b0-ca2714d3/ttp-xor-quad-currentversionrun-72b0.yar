rule TTP_XOR_QUAD_CurrentVersionRun_72b0 {
  strings:
    $key_72b0 = { 21 df [2] 05 d1 [2] 2e fd [2] 00 df [2] 14 c4 [2] 1b de [2] 05 c3 [2] 07 c2 [2] 1c c4 [2] 00 c3 [2] 1c ec }

  condition:
    any of them
}