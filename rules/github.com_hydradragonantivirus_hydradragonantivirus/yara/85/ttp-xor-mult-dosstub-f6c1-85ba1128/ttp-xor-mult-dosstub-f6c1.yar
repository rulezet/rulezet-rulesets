rule TTP_XOR_MULT_DOSStub_f6c1 {
  strings:
    $key_f6c1 = { a2 a9 [2] d6 b1 [2] 91 b3 [2] d6 a2 [2] 98 ae [2] 94 a4 [2] 83 af [2] 98 e1 [2] a5 }

  condition:
    any of them
}