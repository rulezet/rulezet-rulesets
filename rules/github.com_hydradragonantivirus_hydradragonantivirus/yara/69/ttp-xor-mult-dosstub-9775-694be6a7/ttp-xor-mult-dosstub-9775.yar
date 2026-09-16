rule TTP_XOR_MULT_DOSStub_9775 {
  strings:
    $key_9775 = { c3 1d [2] b7 05 [2] f0 07 [2] b7 16 [2] f9 1a [2] f5 10 [2] e2 1b [2] f9 55 [2] c4 }

  condition:
    any of them
}