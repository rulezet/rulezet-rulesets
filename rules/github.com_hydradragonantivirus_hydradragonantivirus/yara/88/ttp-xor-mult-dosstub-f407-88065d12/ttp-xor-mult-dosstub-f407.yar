rule TTP_XOR_MULT_DOSStub_f407 {
  strings:
    $key_f407 = { a0 6f [2] d4 77 [2] 93 75 [2] d4 64 [2] 9a 68 [2] 96 62 [2] 81 69 [2] 9a 27 [2] a7 }

  condition:
    any of them
}