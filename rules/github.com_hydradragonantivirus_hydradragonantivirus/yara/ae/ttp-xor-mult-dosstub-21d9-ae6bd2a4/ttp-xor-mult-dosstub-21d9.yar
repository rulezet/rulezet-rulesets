rule TTP_XOR_MULT_DOSStub_21d9 {
  strings:
    $key_21d9 = { 75 b1 [2] 01 a9 [2] 46 ab [2] 01 ba [2] 4f b6 [2] 43 bc [2] 54 b7 [2] 4f f9 [2] 72 }

  condition:
    any of them
}