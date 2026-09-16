rule TTP_XOR_MULT_DOSStub_dfd6 {
  strings:
    $key_dfd6 = { 8b be [2] ff a6 [2] b8 a4 [2] ff b5 [2] b1 b9 [2] bd b3 [2] aa b8 [2] b1 f6 [2] 8c }

  condition:
    any of them
}