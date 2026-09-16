rule TTP_XOR_MULT_DOSStub_f6b7 {
  strings:
    $key_f6b7 = { a2 df [2] d6 c7 [2] 91 c5 [2] d6 d4 [2] 98 d8 [2] 94 d2 [2] 83 d9 [2] 98 97 [2] a5 }

  condition:
    any of them
}