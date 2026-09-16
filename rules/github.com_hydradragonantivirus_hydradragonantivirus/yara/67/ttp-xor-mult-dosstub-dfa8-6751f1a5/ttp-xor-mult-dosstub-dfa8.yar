rule TTP_XOR_MULT_DOSStub_dfa8 {
  strings:
    $key_dfa8 = { 8b c0 [2] ff d8 [2] b8 da [2] ff cb [2] b1 c7 [2] bd cd [2] aa c6 [2] b1 88 [2] 8c }

  condition:
    any of them
}