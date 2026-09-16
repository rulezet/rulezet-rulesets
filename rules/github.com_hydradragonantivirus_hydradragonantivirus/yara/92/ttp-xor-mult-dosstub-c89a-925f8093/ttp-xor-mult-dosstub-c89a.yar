rule TTP_XOR_MULT_DOSStub_c89a {
  strings:
    $key_c89a = { 9c f2 [2] e8 ea [2] af e8 [2] e8 f9 [2] a6 f5 [2] aa ff [2] bd f4 [2] a6 ba [2] 9b }

  condition:
    any of them
}