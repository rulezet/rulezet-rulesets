rule TTP_XOR_MULT_DOSStub_f4b7 {
  strings:
    $key_f4b7 = { a0 df [2] d4 c7 [2] 93 c5 [2] d4 d4 [2] 9a d8 [2] 96 d2 [2] 81 d9 [2] 9a 97 [2] a7 }

  condition:
    any of them
}