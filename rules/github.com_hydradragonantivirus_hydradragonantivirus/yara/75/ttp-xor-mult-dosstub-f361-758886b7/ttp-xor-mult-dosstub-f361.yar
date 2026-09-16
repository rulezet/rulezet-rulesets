rule TTP_XOR_MULT_DOSStub_f361 {
  strings:
    $key_f361 = { a7 09 [2] d3 11 [2] 94 13 [2] d3 02 [2] 9d 0e [2] 91 04 [2] 86 0f [2] 9d 41 [2] a0 }

  condition:
    any of them
}