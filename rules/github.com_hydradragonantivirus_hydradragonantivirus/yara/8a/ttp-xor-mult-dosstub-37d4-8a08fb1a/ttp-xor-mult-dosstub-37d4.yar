rule TTP_XOR_MULT_DOSStub_37d4 {
  strings:
    $key_37d4 = { 63 bc [2] 17 a4 [2] 50 a6 [2] 17 b7 [2] 59 bb [2] 55 b1 [2] 42 ba [2] 59 f4 [2] 64 }

  condition:
    any of them
}