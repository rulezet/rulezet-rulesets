rule TTP_XOR_MULT_DOSStub_9752 {
  strings:
    $key_9752 = { c3 3a [2] b7 22 [2] f0 20 [2] b7 31 [2] f9 3d [2] f5 37 [2] e2 3c [2] f9 72 [2] c4 }

  condition:
    any of them
}