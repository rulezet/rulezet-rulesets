rule TTP_XOR_MULT_DOSStub_9652 {
  strings:
    $key_9652 = { c2 3a [2] b6 22 [2] f1 20 [2] b6 31 [2] f8 3d [2] f4 37 [2] e3 3c [2] f8 72 [2] c5 }

  condition:
    any of them
}