rule TTP_XOR_MULT_DOSStub_f456 {
  strings:
    $key_f456 = { a0 3e [2] d4 26 [2] 93 24 [2] d4 35 [2] 9a 39 [2] 96 33 [2] 81 38 [2] 9a 76 [2] a7 }

  condition:
    any of them
}