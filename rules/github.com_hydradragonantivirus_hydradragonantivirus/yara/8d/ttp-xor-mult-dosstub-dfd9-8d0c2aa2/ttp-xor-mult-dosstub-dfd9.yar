rule TTP_XOR_MULT_DOSStub_dfd9 {
  strings:
    $key_dfd9 = { 8b b1 [2] ff a9 [2] b8 ab [2] ff ba [2] b1 b6 [2] bd bc [2] aa b7 [2] b1 f9 [2] 8c }

  condition:
    any of them
}