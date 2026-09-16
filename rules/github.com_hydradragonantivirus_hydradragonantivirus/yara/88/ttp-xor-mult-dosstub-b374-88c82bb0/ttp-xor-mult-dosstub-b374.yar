rule TTP_XOR_MULT_DOSStub_b374 {
  strings:
    $key_b374 = { e7 1c [2] 93 04 [2] d4 06 [2] 93 17 [2] dd 1b [2] d1 11 [2] c6 1a [2] dd 54 [2] e0 }

  condition:
    any of them
}