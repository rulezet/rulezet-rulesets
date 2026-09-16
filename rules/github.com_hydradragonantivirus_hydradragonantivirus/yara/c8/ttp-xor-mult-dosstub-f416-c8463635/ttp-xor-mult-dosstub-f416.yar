rule TTP_XOR_MULT_DOSStub_f416 {
  strings:
    $key_f416 = { a0 7e [2] d4 66 [2] 93 64 [2] d4 75 [2] 9a 79 [2] 96 73 [2] 81 78 [2] 9a 36 [2] a7 }

  condition:
    any of them
}