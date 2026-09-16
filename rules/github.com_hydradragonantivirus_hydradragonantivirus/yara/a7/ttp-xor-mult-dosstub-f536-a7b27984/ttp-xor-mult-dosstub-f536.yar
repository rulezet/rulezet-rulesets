rule TTP_XOR_MULT_DOSStub_f536 {
  strings:
    $key_f536 = { a1 5e [2] d5 46 [2] 92 44 [2] d5 55 [2] 9b 59 [2] 97 53 [2] 80 58 [2] 9b 16 [2] a6 }

  condition:
    any of them
}