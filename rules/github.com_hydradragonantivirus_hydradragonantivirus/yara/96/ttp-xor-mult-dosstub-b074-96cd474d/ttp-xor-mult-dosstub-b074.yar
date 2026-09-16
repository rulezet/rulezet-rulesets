rule TTP_XOR_MULT_DOSStub_b074 {
  strings:
    $key_b074 = { e4 1c [2] 90 04 [2] d7 06 [2] 90 17 [2] de 1b [2] d2 11 [2] c5 1a [2] de 54 [2] e3 }

  condition:
    any of them
}