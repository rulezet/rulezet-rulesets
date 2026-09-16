rule TTP_XOR_MULT_DOSStub_f8d4 {
  strings:
    $key_f8d4 = { ac bc [2] d8 a4 [2] 9f a6 [2] d8 b7 [2] 96 bb [2] 9a b1 [2] 8d ba [2] 96 f4 [2] ab }

  condition:
    any of them
}