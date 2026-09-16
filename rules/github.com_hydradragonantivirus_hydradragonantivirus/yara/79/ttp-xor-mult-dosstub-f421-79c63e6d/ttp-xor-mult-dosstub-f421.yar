rule TTP_XOR_MULT_DOSStub_f421 {
  strings:
    $key_f421 = { a0 49 [2] d4 51 [2] 93 53 [2] d4 42 [2] 9a 4e [2] 96 44 [2] 81 4f [2] 9a 01 [2] a7 }

  condition:
    any of them
}