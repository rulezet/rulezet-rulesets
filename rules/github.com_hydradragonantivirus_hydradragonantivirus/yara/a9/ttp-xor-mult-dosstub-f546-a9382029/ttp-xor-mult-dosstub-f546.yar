rule TTP_XOR_MULT_DOSStub_f546 {
  strings:
    $key_f546 = { a1 2e [2] d5 36 [2] 92 34 [2] d5 25 [2] 9b 29 [2] 97 23 [2] 80 28 [2] 9b 66 [2] a6 }

  condition:
    any of them
}