rule TTP_XOR_MULT_DOSStub_9779 {
  strings:
    $key_9779 = { c3 11 [2] b7 09 [2] f0 0b [2] b7 1a [2] f9 16 [2] f5 1c [2] e2 17 [2] f9 59 [2] c4 }

  condition:
    any of them
}