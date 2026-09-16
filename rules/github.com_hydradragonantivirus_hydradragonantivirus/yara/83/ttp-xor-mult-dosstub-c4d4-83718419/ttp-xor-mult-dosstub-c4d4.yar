rule TTP_XOR_MULT_DOSStub_c4d4 {
  strings:
    $key_c4d4 = { 90 bc [2] e4 a4 [2] a3 a6 [2] e4 b7 [2] aa bb [2] a6 b1 [2] b1 ba [2] aa f4 [2] 97 }

  condition:
    any of them
}