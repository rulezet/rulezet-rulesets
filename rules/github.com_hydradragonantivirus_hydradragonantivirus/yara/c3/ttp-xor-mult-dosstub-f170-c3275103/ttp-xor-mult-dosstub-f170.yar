rule TTP_XOR_MULT_DOSStub_f170 {
  strings:
    $key_f170 = { a5 18 [2] d1 00 [2] 96 02 [2] d1 13 [2] 9f 1f [2] 93 15 [2] 84 1e [2] 9f 50 [2] a2 }

  condition:
    any of them
}