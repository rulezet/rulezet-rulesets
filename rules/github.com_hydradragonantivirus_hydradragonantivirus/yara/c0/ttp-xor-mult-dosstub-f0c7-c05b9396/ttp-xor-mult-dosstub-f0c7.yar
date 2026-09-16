rule TTP_XOR_MULT_DOSStub_f0c7 {
  strings:
    $key_f0c7 = { a4 af [2] d0 b7 [2] 97 b5 [2] d0 a4 [2] 9e a8 [2] 92 a2 [2] 85 a9 [2] 9e e7 [2] a3 }

  condition:
    any of them
}