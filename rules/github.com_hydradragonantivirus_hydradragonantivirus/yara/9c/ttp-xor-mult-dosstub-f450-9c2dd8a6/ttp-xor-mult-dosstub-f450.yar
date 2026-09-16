rule TTP_XOR_MULT_DOSStub_f450 {
  strings:
    $key_f450 = { a0 38 [2] d4 20 [2] 93 22 [2] d4 33 [2] 9a 3f [2] 96 35 [2] 81 3e [2] 9a 70 [2] a7 }

  condition:
    any of them
}