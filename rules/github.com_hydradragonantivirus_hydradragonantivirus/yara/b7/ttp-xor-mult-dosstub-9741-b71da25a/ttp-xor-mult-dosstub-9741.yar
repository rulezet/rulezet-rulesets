rule TTP_XOR_MULT_DOSStub_9741 {
  strings:
    $key_9741 = { c3 29 [2] b7 31 [2] f0 33 [2] b7 22 [2] f9 2e [2] f5 24 [2] e2 2f [2] f9 61 [2] c4 }

  condition:
    any of them
}