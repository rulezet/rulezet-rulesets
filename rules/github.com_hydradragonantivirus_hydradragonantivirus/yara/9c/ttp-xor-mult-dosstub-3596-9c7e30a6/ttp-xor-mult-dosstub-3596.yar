rule TTP_XOR_MULT_DOSStub_3596 {
  strings:
    $key_3596 = { 61 fe [2] 15 e6 [2] 52 e4 [2] 15 f5 [2] 5b f9 [2] 57 f3 [2] 40 f8 [2] 5b b6 [2] 66 }

  condition:
    any of them
}