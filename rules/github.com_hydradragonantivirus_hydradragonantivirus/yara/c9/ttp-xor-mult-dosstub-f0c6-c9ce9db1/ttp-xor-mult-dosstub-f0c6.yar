rule TTP_XOR_MULT_DOSStub_f0c6 {
  strings:
    $key_f0c6 = { a4 ae [2] d0 b6 [2] 97 b4 [2] d0 a5 [2] 9e a9 [2] 92 a3 [2] 85 a8 [2] 9e e6 [2] a3 }

  condition:
    any of them
}