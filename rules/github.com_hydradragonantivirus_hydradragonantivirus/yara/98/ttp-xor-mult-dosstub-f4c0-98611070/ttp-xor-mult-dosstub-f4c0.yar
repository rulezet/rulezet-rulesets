rule TTP_XOR_MULT_DOSStub_f4c0 {
  strings:
    $key_f4c0 = { a0 a8 [2] d4 b0 [2] 93 b2 [2] d4 a3 [2] 9a af [2] 96 a5 [2] 81 ae [2] 9a e0 [2] a7 }

  condition:
    any of them
}