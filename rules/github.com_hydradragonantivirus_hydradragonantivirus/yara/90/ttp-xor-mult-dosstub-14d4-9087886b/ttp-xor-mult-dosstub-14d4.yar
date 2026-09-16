rule TTP_XOR_MULT_DOSStub_14d4 {
  strings:
    $key_14d4 = { 40 bc [2] 34 a4 [2] 73 a6 [2] 34 b7 [2] 7a bb [2] 76 b1 [2] 61 ba [2] 7a f4 [2] 47 }

  condition:
    any of them
}