rule TTP_XOR_MULT_DOSStub_9768 {
  strings:
    $key_9768 = { c3 00 [2] b7 18 [2] f0 1a [2] b7 0b [2] f9 07 [2] f5 0d [2] e2 06 [2] f9 48 [2] c4 }

  condition:
    any of them
}