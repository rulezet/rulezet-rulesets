rule TTP_XOR_MULT_DOSStub_67d9 {
  strings:
    $key_67d9 = { 33 b1 [2] 47 a9 [2] 00 ab [2] 47 ba [2] 09 b6 [2] 05 bc [2] 12 b7 [2] 09 f9 [2] 34 }

  condition:
    any of them
}