rule TTP_XOR_MULT_DOSStub_f459 {
  strings:
    $key_f459 = { a0 31 [2] d4 29 [2] 93 2b [2] d4 3a [2] 9a 36 [2] 96 3c [2] 81 37 [2] 9a 79 [2] a7 }

  condition:
    any of them
}