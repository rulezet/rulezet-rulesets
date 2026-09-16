rule TTP_XOR_MULT_DOSStub_7ec1 {
  strings:
    $key_7ec1 = { 2a a9 [2] 5e b1 [2] 19 b3 [2] 5e a2 [2] 10 ae [2] 1c a4 [2] 0b af [2] 10 e1 [2] 2d }

  condition:
    any of them
}