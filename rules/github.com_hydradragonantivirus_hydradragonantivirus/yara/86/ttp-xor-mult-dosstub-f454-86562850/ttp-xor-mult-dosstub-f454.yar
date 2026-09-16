rule TTP_XOR_MULT_DOSStub_f454 {
  strings:
    $key_f454 = { a0 3c [2] d4 24 [2] 93 26 [2] d4 37 [2] 9a 3b [2] 96 31 [2] 81 3a [2] 9a 74 [2] a7 }

  condition:
    any of them
}