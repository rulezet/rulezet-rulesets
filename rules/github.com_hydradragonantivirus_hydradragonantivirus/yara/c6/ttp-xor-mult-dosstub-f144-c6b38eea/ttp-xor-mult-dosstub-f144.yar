rule TTP_XOR_MULT_DOSStub_f144 {
  strings:
    $key_f144 = { a5 2c [2] d1 34 [2] 96 36 [2] d1 27 [2] 9f 2b [2] 93 21 [2] 84 2a [2] 9f 64 [2] a2 }

  condition:
    any of them
}