rule TTP_XOR_MULT_DOSStub_f174 {
  strings:
    $key_f174 = { a5 1c [2] d1 04 [2] 96 06 [2] d1 17 [2] 9f 1b [2] 93 11 [2] 84 1a [2] 9f 54 [2] a2 }

  condition:
    any of them
}