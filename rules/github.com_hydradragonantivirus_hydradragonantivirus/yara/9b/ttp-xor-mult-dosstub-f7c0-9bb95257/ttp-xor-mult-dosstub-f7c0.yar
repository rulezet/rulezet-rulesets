rule TTP_XOR_MULT_DOSStub_f7c0 {
  strings:
    $key_f7c0 = { a3 a8 [2] d7 b0 [2] 90 b2 [2] d7 a3 [2] 99 af [2] 95 a5 [2] 82 ae [2] 99 e0 [2] a4 }

  condition:
    any of them
}