rule TTP_XOR_MULT_DOSStub_f4c5 {
  strings:
    $key_f4c5 = { a0 ad [2] d4 b5 [2] 93 b7 [2] d4 a6 [2] 9a aa [2] 96 a0 [2] 81 ab [2] 9a e5 [2] a7 }

  condition:
    any of them
}