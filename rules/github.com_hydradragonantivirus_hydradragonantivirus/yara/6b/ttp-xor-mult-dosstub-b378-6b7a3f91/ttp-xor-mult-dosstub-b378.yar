rule TTP_XOR_MULT_DOSStub_b378 {
  strings:
    $key_b378 = { e7 10 [2] 93 08 [2] d4 0a [2] 93 1b [2] dd 17 [2] d1 1d [2] c6 16 [2] dd 58 [2] e0 }

  condition:
    any of them
}