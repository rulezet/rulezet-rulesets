rule TTP_XOR_MULT_DOSStub_f4f6 {
  strings:
    $key_f4f6 = { a0 9e [2] d4 86 [2] 93 84 [2] d4 95 [2] 9a 99 [2] 96 93 [2] 81 98 [2] 9a d6 [2] a7 }

  condition:
    any of them
}