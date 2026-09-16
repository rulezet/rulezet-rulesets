rule TTP_XOR_MULT_DOSStub_f468 {
  strings:
    $key_f468 = { a0 00 [2] d4 18 [2] 93 1a [2] d4 0b [2] 9a 07 [2] 96 0d [2] 81 06 [2] 9a 48 [2] a7 }

  condition:
    any of them
}