rule TTP_XOR_MULT_DOSStub_1cd9 {
  strings:
    $key_1cd9 = { 48 b1 [2] 3c a9 [2] 7b ab [2] 3c ba [2] 72 b6 [2] 7e bc [2] 69 b7 [2] 72 f9 [2] 4f }

  condition:
    any of them
}