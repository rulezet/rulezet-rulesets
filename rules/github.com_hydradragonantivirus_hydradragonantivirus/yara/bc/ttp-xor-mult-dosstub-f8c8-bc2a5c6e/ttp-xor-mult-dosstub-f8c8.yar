rule TTP_XOR_MULT_DOSStub_f8c8 {
  strings:
    $key_f8c8 = { ac a0 [2] d8 b8 [2] 9f ba [2] d8 ab [2] 96 a7 [2] 9a ad [2] 8d a6 [2] 96 e8 [2] ab }

  condition:
    any of them
}