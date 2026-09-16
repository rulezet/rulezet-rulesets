rule TTP_XOR_MULT_DOSStub_f477 {
  strings:
    $key_f477 = { a0 1f [2] d4 07 [2] 93 05 [2] d4 14 [2] 9a 18 [2] 96 12 [2] 81 19 [2] 9a 57 [2] a7 }

  condition:
    any of them
}