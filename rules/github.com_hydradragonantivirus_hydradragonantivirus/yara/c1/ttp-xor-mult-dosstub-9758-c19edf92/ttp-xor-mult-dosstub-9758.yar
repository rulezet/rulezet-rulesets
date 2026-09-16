rule TTP_XOR_MULT_DOSStub_9758 {
  strings:
    $key_9758 = { c3 30 [2] b7 28 [2] f0 2a [2] b7 3b [2] f9 37 [2] f5 3d [2] e2 36 [2] f9 78 [2] c4 }

  condition:
    any of them
}