rule TTP_XOR_MULT_DOSStub_9052 {
  strings:
    $key_9052 = { c4 3a [2] b0 22 [2] f7 20 [2] b0 31 [2] fe 3d [2] f2 37 [2] e5 3c [2] fe 72 [2] c3 }

  condition:
    any of them
}