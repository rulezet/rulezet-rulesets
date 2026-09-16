rule TTP_XOR_MULT_DOSStub_33d9 {
  strings:
    $key_33d9 = { 67 b1 [2] 13 a9 [2] 54 ab [2] 13 ba [2] 5d b6 [2] 51 bc [2] 46 b7 [2] 5d f9 [2] 60 }

  condition:
    any of them
}