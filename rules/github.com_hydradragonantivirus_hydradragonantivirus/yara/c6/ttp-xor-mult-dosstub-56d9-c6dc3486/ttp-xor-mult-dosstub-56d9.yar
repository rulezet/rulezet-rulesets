rule TTP_XOR_MULT_DOSStub_56d9 {
  strings:
    $key_56d9 = { 02 b1 [2] 76 a9 [2] 31 ab [2] 76 ba [2] 38 b6 [2] 34 bc [2] 23 b7 [2] 38 f9 [2] 05 }

  condition:
    any of them
}