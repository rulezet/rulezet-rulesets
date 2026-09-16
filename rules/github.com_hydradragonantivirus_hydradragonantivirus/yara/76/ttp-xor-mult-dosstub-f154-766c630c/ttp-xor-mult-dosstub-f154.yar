rule TTP_XOR_MULT_DOSStub_f154 {
  strings:
    $key_f154 = { a5 3c [2] d1 24 [2] 96 26 [2] d1 37 [2] 9f 3b [2] 93 31 [2] 84 3a [2] 9f 74 [2] a2 }

  condition:
    any of them
}