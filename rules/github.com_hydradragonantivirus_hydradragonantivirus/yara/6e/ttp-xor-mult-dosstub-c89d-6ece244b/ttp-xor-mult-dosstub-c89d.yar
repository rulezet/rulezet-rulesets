rule TTP_XOR_MULT_DOSStub_c89d {
  strings:
    $key_c89d = { 9c f5 [2] e8 ed [2] af ef [2] e8 fe [2] a6 f2 [2] aa f8 [2] bd f3 [2] a6 bd [2] 9b }

  condition:
    any of them
}