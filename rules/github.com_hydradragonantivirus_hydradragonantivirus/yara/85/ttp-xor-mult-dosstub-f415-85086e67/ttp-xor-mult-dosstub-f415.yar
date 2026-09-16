rule TTP_XOR_MULT_DOSStub_f415 {
  strings:
    $key_f415 = { a0 7d [2] d4 65 [2] 93 67 [2] d4 76 [2] 9a 7a [2] 96 70 [2] 81 7b [2] 9a 35 [2] a7 }

  condition:
    any of them
}