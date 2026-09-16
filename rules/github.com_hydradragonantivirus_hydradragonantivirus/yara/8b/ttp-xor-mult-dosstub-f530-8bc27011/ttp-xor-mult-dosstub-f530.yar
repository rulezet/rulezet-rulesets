rule TTP_XOR_MULT_DOSStub_f530 {
  strings:
    $key_f530 = { a1 58 [2] d5 40 [2] 92 42 [2] d5 53 [2] 9b 5f [2] 97 55 [2] 80 5e [2] 9b 10 [2] a6 }

  condition:
    any of them
}