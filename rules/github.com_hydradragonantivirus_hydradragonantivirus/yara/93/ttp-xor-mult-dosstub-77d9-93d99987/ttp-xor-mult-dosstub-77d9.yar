rule TTP_XOR_MULT_DOSStub_77d9 {
  strings:
    $key_77d9 = { 23 b1 [2] 57 a9 [2] 10 ab [2] 57 ba [2] 19 b6 [2] 15 bc [2] 02 b7 [2] 19 f9 [2] 24 }

  condition:
    any of them
}