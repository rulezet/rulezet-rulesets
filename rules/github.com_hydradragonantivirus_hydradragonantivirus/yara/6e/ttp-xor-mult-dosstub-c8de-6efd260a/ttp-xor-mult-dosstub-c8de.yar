rule TTP_XOR_MULT_DOSStub_c8de {
  strings:
    $key_c8de = { 9c b6 [2] e8 ae [2] af ac [2] e8 bd [2] a6 b1 [2] aa bb [2] bd b0 [2] a6 fe [2] 9b }

  condition:
    any of them
}