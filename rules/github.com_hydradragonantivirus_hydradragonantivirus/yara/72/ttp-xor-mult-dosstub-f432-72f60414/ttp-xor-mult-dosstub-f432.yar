rule TTP_XOR_MULT_DOSStub_f432 {
  strings:
    $key_f432 = { a0 5a [2] d4 42 [2] 93 40 [2] d4 51 [2] 9a 5d [2] 96 57 [2] 81 5c [2] 9a 12 [2] a7 }

  condition:
    any of them
}