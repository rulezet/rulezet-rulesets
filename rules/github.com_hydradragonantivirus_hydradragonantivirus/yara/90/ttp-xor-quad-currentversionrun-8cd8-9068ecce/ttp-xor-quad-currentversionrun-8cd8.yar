rule TTP_XOR_QUAD_CurrentVersionRun_8cd8 {
  strings:
    $key_8cd8 = { df b7 [2] fb b9 [2] d0 95 [2] fe b7 [2] ea ac [2] e5 b6 [2] fb ab [2] f9 aa [2] e2 ac [2] fe ab [2] e2 84 }

  condition:
    any of them
}