rule TTP_XOR_MULT_DOSStub_f449 {
  strings:
    $key_f449 = { a0 21 [2] d4 39 [2] 93 3b [2] d4 2a [2] 9a 26 [2] 96 2c [2] 81 27 [2] 9a 69 [2] a7 }

  condition:
    any of them
}