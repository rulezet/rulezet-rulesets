rule TTP_XOR_MULT_DOSStub_75d9 {
  strings:
    $key_75d9 = { 21 b1 [2] 55 a9 [2] 12 ab [2] 55 ba [2] 1b b6 [2] 17 bc [2] 00 b7 [2] 1b f9 [2] 26 }

  condition:
    any of them
}