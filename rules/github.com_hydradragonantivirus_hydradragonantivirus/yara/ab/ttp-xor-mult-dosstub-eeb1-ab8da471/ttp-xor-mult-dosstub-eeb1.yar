rule TTP_XOR_MULT_DOSStub_eeb1 {
  strings:
    $key_eeb1 = { ba d9 [2] ce c1 [2] 89 c3 [2] ce d2 [2] 80 de [2] 8c d4 [2] 9b df [2] 80 91 [2] bd }

  condition:
    any of them
}