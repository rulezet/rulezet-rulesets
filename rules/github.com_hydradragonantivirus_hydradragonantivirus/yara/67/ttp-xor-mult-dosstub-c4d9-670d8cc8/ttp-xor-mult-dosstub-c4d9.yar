rule TTP_XOR_MULT_DOSStub_c4d9 {
  strings:
    $key_c4d9 = { 90 b1 [2] e4 a9 [2] a3 ab [2] e4 ba [2] aa b6 [2] a6 bc [2] b1 b7 [2] aa f9 [2] 97 }

  condition:
    any of them
}