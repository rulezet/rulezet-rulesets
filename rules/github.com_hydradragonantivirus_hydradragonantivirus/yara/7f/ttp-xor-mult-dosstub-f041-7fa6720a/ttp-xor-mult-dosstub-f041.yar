rule TTP_XOR_MULT_DOSStub_f041 {
  strings:
    $key_f041 = { a4 29 [2] d0 31 [2] 97 33 [2] d0 22 [2] 9e 2e [2] 92 24 [2] 85 2f [2] 9e 61 [2] a3 }

  condition:
    any of them
}