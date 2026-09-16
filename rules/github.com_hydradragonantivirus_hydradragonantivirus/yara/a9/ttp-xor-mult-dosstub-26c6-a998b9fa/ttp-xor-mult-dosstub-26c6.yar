rule TTP_XOR_MULT_DOSStub_26c6 {
  strings:
    $key_26c6 = { 72 ae [2] 06 b6 [2] 41 b4 [2] 06 a5 [2] 48 a9 [2] 44 a3 [2] 53 a8 [2] 48 e6 [2] 75 }

  condition:
    any of them
}