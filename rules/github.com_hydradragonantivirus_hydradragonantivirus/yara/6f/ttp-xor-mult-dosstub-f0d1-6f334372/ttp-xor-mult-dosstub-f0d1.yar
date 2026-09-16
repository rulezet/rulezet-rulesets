rule TTP_XOR_MULT_DOSStub_f0d1 {
  strings:
    $key_f0d1 = { a4 b9 [2] d0 a1 [2] 97 a3 [2] d0 b2 [2] 9e be [2] 92 b4 [2] 85 bf [2] 9e f1 [2] a3 }

  condition:
    any of them
}