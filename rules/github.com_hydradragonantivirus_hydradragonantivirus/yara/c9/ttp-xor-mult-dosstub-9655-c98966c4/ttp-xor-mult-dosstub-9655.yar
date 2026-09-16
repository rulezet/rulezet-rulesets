rule TTP_XOR_MULT_DOSStub_9655 {
  strings:
    $key_9655 = { c2 3d [2] b6 25 [2] f1 27 [2] b6 36 [2] f8 3a [2] f4 30 [2] e3 3b [2] f8 75 [2] c5 }

  condition:
    any of them
}