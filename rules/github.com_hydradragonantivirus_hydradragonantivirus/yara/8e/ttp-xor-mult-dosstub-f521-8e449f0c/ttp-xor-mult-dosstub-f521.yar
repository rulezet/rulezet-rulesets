rule TTP_XOR_MULT_DOSStub_f521 {
  strings:
    $key_f521 = { a1 49 [2] d5 51 [2] 92 53 [2] d5 42 [2] 9b 4e [2] 97 44 [2] 80 4f [2] 9b 01 [2] a6 }

  condition:
    any of them
}