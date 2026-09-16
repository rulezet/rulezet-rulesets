rule TTP_XOR_MULT_DOSStub_0596 {
  strings:
    $key_0596 = { 51 fe [2] 25 e6 [2] 62 e4 [2] 25 f5 [2] 6b f9 [2] 67 f3 [2] 70 f8 [2] 6b b6 [2] 56 }

  condition:
    any of them
}