rule TTP_XOR_MULT_DOSStub_f479 {
  strings:
    $key_f479 = { a0 11 [2] d4 09 [2] 93 0b [2] d4 1a [2] 9a 16 [2] 96 1c [2] 81 17 [2] 9a 59 [2] a7 }

  condition:
    any of them
}