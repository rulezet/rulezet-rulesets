rule TTP_XOR_MULT_DOSStub_31d9 {
  strings:
    $key_31d9 = { 65 b1 [2] 11 a9 [2] 56 ab [2] 11 ba [2] 5f b6 [2] 53 bc [2] 44 b7 [2] 5f f9 [2] 62 }

  condition:
    any of them
}