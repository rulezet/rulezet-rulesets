rule TTP_XOR_MULT_DOSStub_f8c3 {
  strings:
    $key_f8c3 = { ac ab [2] d8 b3 [2] 9f b1 [2] d8 a0 [2] 96 ac [2] 9a a6 [2] 8d ad [2] 96 e3 [2] ab }

  condition:
    any of them
}