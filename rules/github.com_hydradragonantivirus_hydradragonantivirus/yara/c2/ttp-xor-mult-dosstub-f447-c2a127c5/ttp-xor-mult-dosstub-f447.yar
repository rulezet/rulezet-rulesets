rule TTP_XOR_MULT_DOSStub_f447 {
  strings:
    $key_f447 = { a0 2f [2] d4 37 [2] 93 35 [2] d4 24 [2] 9a 28 [2] 96 22 [2] 81 29 [2] 9a 67 [2] a7 }

  condition:
    any of them
}