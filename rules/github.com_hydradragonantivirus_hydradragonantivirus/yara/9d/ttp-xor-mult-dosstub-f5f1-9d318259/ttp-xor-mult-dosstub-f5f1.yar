rule TTP_XOR_MULT_DOSStub_f5f1 {
  strings:
    $key_f5f1 = { a1 99 [2] d5 81 [2] 92 83 [2] d5 92 [2] 9b 9e [2] 97 94 [2] 80 9f [2] 9b d1 [2] a6 }

  condition:
    any of them
}