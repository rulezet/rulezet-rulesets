rule TTP_XOR_MULT_DOSStub_9717 {
  strings:
    $key_9717 = { c3 7f [2] b7 67 [2] f0 65 [2] b7 74 [2] f9 78 [2] f5 72 [2] e2 79 [2] f9 37 [2] c4 }

  condition:
    any of them
}