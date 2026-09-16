rule TTP_XOR_MULT_DOSStub_f176 {
  strings:
    $key_f176 = { a5 1e [2] d1 06 [2] 96 04 [2] d1 15 [2] 9f 19 [2] 93 13 [2] 84 18 [2] 9f 56 [2] a2 }

  condition:
    any of them
}