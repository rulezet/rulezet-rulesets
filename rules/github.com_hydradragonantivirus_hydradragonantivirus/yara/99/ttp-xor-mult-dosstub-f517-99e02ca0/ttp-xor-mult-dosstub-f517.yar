rule TTP_XOR_MULT_DOSStub_f517 {
  strings:
    $key_f517 = { a1 7f [2] d5 67 [2] 92 65 [2] d5 74 [2] 9b 78 [2] 97 72 [2] 80 79 [2] 9b 37 [2] a6 }

  condition:
    any of them
}