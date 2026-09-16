rule TTP_XOR_MULT_DOSStub_46d9 {
  strings:
    $key_46d9 = { 12 b1 [2] 66 a9 [2] 21 ab [2] 66 ba [2] 28 b6 [2] 24 bc [2] 33 b7 [2] 28 f9 [2] 15 }

  condition:
    any of them
}