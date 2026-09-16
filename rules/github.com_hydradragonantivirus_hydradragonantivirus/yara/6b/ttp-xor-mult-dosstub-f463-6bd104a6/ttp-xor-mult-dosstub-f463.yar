rule TTP_XOR_MULT_DOSStub_f463 {
  strings:
    $key_f463 = { a0 0b [2] d4 13 [2] 93 11 [2] d4 00 [2] 9a 0c [2] 96 06 [2] 81 0d [2] 9a 43 [2] a7 }

  condition:
    any of them
}