rule TTP_XOR_MULT_DOSStub_b375 {
  strings:
    $key_b375 = { e7 1d [2] 93 05 [2] d4 07 [2] 93 16 [2] dd 1a [2] d1 10 [2] c6 1b [2] dd 55 [2] e0 }

  condition:
    any of them
}