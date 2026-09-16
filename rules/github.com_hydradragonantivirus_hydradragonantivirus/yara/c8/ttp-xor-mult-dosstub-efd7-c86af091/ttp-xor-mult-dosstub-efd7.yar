rule TTP_XOR_MULT_DOSStub_efd7 {
  strings:
    $key_efd7 = { bb bf [2] cf a7 [2] 88 a5 [2] cf b4 [2] 81 b8 [2] 8d b2 [2] 9a b9 [2] 81 f7 [2] bc }

  condition:
    any of them
}