rule TTP_XOR_MULT_DOSStub_07d9 {
  strings:
    $key_07d9 = { 53 b1 [2] 27 a9 [2] 60 ab [2] 27 ba [2] 69 b6 [2] 65 bc [2] 72 b7 [2] 69 f9 [2] 54 }

  condition:
    any of them
}