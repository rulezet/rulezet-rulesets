rule TTP_XOR_MULT_DOSStub_f4f0 {
  strings:
    $key_f4f0 = { a0 98 [2] d4 80 [2] 93 82 [2] d4 93 [2] 9a 9f [2] 96 95 [2] 81 9e [2] 9a d0 [2] a7 }

  condition:
    any of them
}