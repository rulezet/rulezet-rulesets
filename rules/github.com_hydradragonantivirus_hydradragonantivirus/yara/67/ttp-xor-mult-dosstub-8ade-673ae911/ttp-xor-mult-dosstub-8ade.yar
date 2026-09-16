rule TTP_XOR_MULT_DOSStub_8ade {
  strings:
    $key_8ade = { de b6 [2] aa ae [2] ed ac [2] aa bd [2] e4 b1 [2] e8 bb [2] ff b0 [2] e4 fe [2] d9 }

  condition:
    any of them
}