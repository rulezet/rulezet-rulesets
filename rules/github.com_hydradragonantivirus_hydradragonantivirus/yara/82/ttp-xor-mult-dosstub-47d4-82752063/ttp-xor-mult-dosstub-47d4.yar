rule TTP_XOR_MULT_DOSStub_47d4 {
  strings:
    $key_47d4 = { 13 bc [2] 67 a4 [2] 20 a6 [2] 67 b7 [2] 29 bb [2] 25 b1 [2] 32 ba [2] 29 f4 [2] 14 }

  condition:
    any of them
}