rule TTP_XOR_MULT_DOSStub_9763 {
  strings:
    $key_9763 = { c3 0b [2] b7 13 [2] f0 11 [2] b7 00 [2] f9 0c [2] f5 06 [2] e2 0d [2] f9 43 [2] c4 }

  condition:
    any of them
}