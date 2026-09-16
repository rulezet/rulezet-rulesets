rule TTP_XOR_MULT_DOSStub_1cc8 {
  strings:
    $key_1cc8 = { 48 a0 [2] 3c b8 [2] 7b ba [2] 3c ab [2] 72 a7 [2] 7e ad [2] 69 a6 [2] 72 e8 [2] 4f }

  condition:
    any of them
}