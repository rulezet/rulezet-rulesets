rule TTP_XOR_MULT_DOSStub_b776 {
  strings:
    $key_b776 = { e3 1e [2] 97 06 [2] d0 04 [2] 97 15 [2] d9 19 [2] d5 13 [2] c2 18 [2] d9 56 [2] e4 }

  condition:
    any of them
}