rule TTP_XOR_MULT_DOSStub_f175 {
  strings:
    $key_f175 = { a5 1d [2] d1 05 [2] 96 07 [2] d1 16 [2] 9f 1a [2] 93 10 [2] 84 1b [2] 9f 55 [2] a2 }

  condition:
    any of them
}