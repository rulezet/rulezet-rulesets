rule TTP_XOR_MULT_DOSStub_f451 {
  strings:
    $key_f451 = { a0 39 [2] d4 21 [2] 93 23 [2] d4 32 [2] 9a 3e [2] 96 34 [2] 81 3f [2] 9a 71 [2] a7 }

  condition:
    any of them
}