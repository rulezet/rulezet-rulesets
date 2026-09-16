rule TTP_XOR_MULT_DOSStub_f1d1 {
  strings:
    $key_f1d1 = { a5 b9 [2] d1 a1 [2] 96 a3 [2] d1 b2 [2] 9f be [2] 93 b4 [2] 84 bf [2] 9f f1 [2] a2 }

  condition:
    any of them
}