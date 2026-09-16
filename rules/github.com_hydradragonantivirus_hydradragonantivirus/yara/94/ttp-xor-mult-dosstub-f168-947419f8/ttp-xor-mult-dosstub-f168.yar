rule TTP_XOR_MULT_DOSStub_f168 {
  strings:
    $key_f168 = { a5 00 [2] d1 18 [2] 96 1a [2] d1 0b [2] 9f 07 [2] 93 0d [2] 84 06 [2] 9f 48 [2] a2 }

  condition:
    any of them
}