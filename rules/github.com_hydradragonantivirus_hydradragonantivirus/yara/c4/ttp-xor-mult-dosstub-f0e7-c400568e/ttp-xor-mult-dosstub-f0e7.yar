rule TTP_XOR_MULT_DOSStub_f0e7 {
  strings:
    $key_f0e7 = { a4 8f [2] d0 97 [2] 97 95 [2] d0 84 [2] 9e 88 [2] 92 82 [2] 85 89 [2] 9e c7 [2] a3 }

  condition:
    any of them
}