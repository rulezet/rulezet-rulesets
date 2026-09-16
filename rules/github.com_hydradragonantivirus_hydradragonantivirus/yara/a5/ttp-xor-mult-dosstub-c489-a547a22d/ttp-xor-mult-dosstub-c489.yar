rule TTP_XOR_MULT_DOSStub_c489 {
  strings:
    $key_c489 = { 90 e1 [2] e4 f9 [2] a3 fb [2] e4 ea [2] aa e6 [2] a6 ec [2] b1 e7 [2] aa a9 [2] 97 }

  condition:
    any of them
}