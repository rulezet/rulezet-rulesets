rule TTP_XOR_MULT_DOSStub_f547 {
  strings:
    $key_f547 = { a1 2f [2] d5 37 [2] 92 35 [2] d5 24 [2] 9b 28 [2] 97 22 [2] 80 29 [2] 9b 67 [2] a6 }

  condition:
    any of them
}