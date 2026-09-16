rule TTP_XOR_MULT_DOSStub_dfd5 {
  strings:
    $key_dfd5 = { 8b bd [2] ff a5 [2] b8 a7 [2] ff b6 [2] b1 ba [2] bd b0 [2] aa bb [2] b1 f5 [2] 8c }

  condition:
    any of them
}