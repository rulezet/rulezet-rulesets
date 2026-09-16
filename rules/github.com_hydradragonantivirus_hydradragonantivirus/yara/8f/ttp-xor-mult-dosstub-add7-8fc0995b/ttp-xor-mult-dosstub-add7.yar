rule TTP_XOR_MULT_DOSStub_add7 {
  strings:
    $key_add7 = { f9 bf [2] 8d a7 [2] ca a5 [2] 8d b4 [2] c3 b8 [2] cf b2 [2] d8 b9 [2] c3 f7 [2] fe }

  condition:
    any of them
}