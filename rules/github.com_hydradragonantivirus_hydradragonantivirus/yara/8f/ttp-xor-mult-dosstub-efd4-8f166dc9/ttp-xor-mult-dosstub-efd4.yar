rule TTP_XOR_MULT_DOSStub_efd4 {
  strings:
    $key_efd4 = { bb bc [2] cf a4 [2] 88 a6 [2] cf b7 [2] 81 bb [2] 8d b1 [2] 9a ba [2] 81 f4 [2] bc }

  condition:
    any of them
}