rule TTP_XOR_MULT_DOSStub_f6d1 {
  strings:
    $key_f6d1 = { a2 b9 [2] d6 a1 [2] 91 a3 [2] d6 b2 [2] 98 be [2] 94 b4 [2] 83 bf [2] 98 f1 [2] a5 }

  condition:
    any of them
}