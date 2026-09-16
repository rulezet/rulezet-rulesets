rule TTP_XOR_MULT_DOSStub_7ec7 {
  strings:
    $key_7ec7 = { 2a af [2] 5e b7 [2] 19 b5 [2] 5e a4 [2] 10 a8 [2] 1c a2 [2] 0b a9 [2] 10 e7 [2] 2d }

  condition:
    any of them
}