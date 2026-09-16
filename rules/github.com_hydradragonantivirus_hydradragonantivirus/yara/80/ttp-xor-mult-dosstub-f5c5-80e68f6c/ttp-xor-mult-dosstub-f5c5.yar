rule TTP_XOR_MULT_DOSStub_f5c5 {
  strings:
    $key_f5c5 = { a1 ad [2] d5 b5 [2] 92 b7 [2] d5 a6 [2] 9b aa [2] 97 a0 [2] 80 ab [2] 9b e5 [2] a6 }

  condition:
    any of them
}