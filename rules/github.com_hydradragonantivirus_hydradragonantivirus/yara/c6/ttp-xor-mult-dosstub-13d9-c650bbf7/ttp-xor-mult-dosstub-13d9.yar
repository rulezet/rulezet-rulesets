rule TTP_XOR_MULT_DOSStub_13d9 {
  strings:
    $key_13d9 = { 47 b1 [2] 33 a9 [2] 74 ab [2] 33 ba [2] 7d b6 [2] 71 bc [2] 66 b7 [2] 7d f9 [2] 40 }

  condition:
    any of them
}