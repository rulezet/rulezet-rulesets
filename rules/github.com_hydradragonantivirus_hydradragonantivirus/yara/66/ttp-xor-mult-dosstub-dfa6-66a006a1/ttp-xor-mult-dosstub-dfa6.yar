rule TTP_XOR_MULT_DOSStub_dfa6 {
  strings:
    $key_dfa6 = { 8b ce [2] ff d6 [2] b8 d4 [2] ff c5 [2] b1 c9 [2] bd c3 [2] aa c8 [2] b1 86 [2] 8c }

  condition:
    any of them
}