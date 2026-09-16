rule TTP_XOR_MULT_DOSStub_f7b7 {
  strings:
    $key_f7b7 = { a3 df [2] d7 c7 [2] 90 c5 [2] d7 d4 [2] 99 d8 [2] 95 d2 [2] 82 d9 [2] 99 97 [2] a4 }

  condition:
    any of them
}