rule TTP_XOR_MULT_DOSStub_9745 {
  strings:
    $key_9745 = { c3 2d [2] b7 35 [2] f0 37 [2] b7 26 [2] f9 2a [2] f5 20 [2] e2 2b [2] f9 65 [2] c4 }

  condition:
    any of them
}