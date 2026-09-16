rule TTP_XOR_MULT_DOSStub_76d4 {
  strings:
    $key_76d4 = { 22 bc [2] 56 a4 [2] 11 a6 [2] 56 b7 [2] 18 bb [2] 14 b1 [2] 03 ba [2] 18 f4 [2] 25 }

  condition:
    any of them
}