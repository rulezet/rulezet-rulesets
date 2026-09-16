rule TTP_XOR_MULT_DOSStub_f3b7 {
  strings:
    $key_f3b7 = { a7 df [2] d3 c7 [2] 94 c5 [2] d3 d4 [2] 9d d8 [2] 91 d2 [2] 86 d9 [2] 9d 97 [2] a0 }

  condition:
    any of them
}