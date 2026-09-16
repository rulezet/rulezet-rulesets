rule TTP_XOR_MULT_DOSStub_f436 {
  strings:
    $key_f436 = { a0 5e [2] d4 46 [2] 93 44 [2] d4 55 [2] 9a 59 [2] 96 53 [2] 81 58 [2] 9a 16 [2] a7 }

  condition:
    any of them
}