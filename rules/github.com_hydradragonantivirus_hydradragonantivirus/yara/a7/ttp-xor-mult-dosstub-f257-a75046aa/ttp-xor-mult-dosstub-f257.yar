rule TTP_XOR_MULT_DOSStub_f257 {
  strings:
    $key_f257 = { a6 3f [2] d2 27 [2] 95 25 [2] d2 34 [2] 9c 38 [2] 90 32 [2] 87 39 [2] 9c 77 [2] a1 }

  condition:
    any of them
}