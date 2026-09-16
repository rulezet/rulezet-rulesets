rule TTP_XOR_MULT_DOSStub_f8a0 {
  strings:
    $key_f8a0 = { ac c8 [2] d8 d0 [2] 9f d2 [2] d8 c3 [2] 96 cf [2] 9a c5 [2] 8d ce [2] 96 80 [2] ab }

  condition:
    any of them
}