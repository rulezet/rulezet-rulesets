rule TTP_XOR_MULT_DOSStub_f470 {
  strings:
    $key_f470 = { a0 18 [2] d4 00 [2] 93 02 [2] d4 13 [2] 9a 1f [2] 96 15 [2] 81 1e [2] 9a 50 [2] a7 }

  condition:
    any of them
}