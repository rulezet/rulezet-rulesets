rule TTP_XOR_MULT_DOSStub_f0c5 {
  strings:
    $key_f0c5 = { a4 ad [2] d0 b5 [2] 97 b7 [2] d0 a6 [2] 9e aa [2] 92 a0 [2] 85 ab [2] 9e e5 [2] a3 }

  condition:
    any of them
}