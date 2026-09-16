rule TTP_XOR_MULT_DOSStub_26d9 {
  strings:
    $key_26d9 = { 72 b1 [2] 06 a9 [2] 41 ab [2] 06 ba [2] 48 b6 [2] 44 bc [2] 53 b7 [2] 48 f9 [2] 75 }

  condition:
    any of them
}