rule TTP_XOR_MULT_DOSStub_dfd7 {
  strings:
    $key_dfd7 = { 8b bf [2] ff a7 [2] b8 a5 [2] ff b4 [2] b1 b8 [2] bd b2 [2] aa b9 [2] b1 f7 [2] 8c }

  condition:
    any of them
}