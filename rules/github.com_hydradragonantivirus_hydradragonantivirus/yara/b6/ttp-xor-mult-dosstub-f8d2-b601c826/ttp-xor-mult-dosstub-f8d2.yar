rule TTP_XOR_MULT_DOSStub_f8d2 {
  strings:
    $key_f8d2 = { ac ba [2] d8 a2 [2] 9f a0 [2] d8 b1 [2] 96 bd [2] 9a b7 [2] 8d bc [2] 96 f2 [2] ab }

  condition:
    any of them
}