rule TTP_XOR_MULT_DOSStub_dade {
  strings:
    $key_dade = { 8e b6 [2] fa ae [2] bd ac [2] fa bd [2] b4 b1 [2] b8 bb [2] af b0 [2] b4 fe [2] 89 }

  condition:
    any of them
}