rule TTP_XOR_MULT_DOSStub_6cc6 {
  strings:
    $key_6cc6 = { 38 ae [2] 4c b6 [2] 0b b4 [2] 4c a5 [2] 02 a9 [2] 0e a3 [2] 19 a8 [2] 02 e6 [2] 3f }

  condition:
    any of them
}