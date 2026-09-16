rule TTP_XOR_MULT_DOSStub_efd9 {
  strings:
    $key_efd9 = { bb b1 [2] cf a9 [2] 88 ab [2] cf ba [2] 81 b6 [2] 8d bc [2] 9a b7 [2] 81 f9 [2] bc }

  condition:
    any of them
}