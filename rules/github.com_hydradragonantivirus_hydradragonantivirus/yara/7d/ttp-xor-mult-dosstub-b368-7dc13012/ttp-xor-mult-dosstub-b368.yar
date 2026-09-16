rule TTP_XOR_MULT_DOSStub_b368 {
  strings:
    $key_b368 = { e7 00 [2] 93 18 [2] d4 1a [2] 93 0b [2] dd 07 [2] d1 0d [2] c6 06 [2] dd 48 [2] e0 }

  condition:
    any of them
}