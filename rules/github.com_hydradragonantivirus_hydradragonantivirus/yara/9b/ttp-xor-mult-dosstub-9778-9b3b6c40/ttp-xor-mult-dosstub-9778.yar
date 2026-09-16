rule TTP_XOR_MULT_DOSStub_9778 {
  strings:
    $key_9778 = { c3 10 [2] b7 08 [2] f0 0a [2] b7 1b [2] f9 17 [2] f5 1d [2] e2 16 [2] f9 58 [2] c4 }

  condition:
    any of them
}