rule TTP_XOR_MULT_DOSStub_9653 {
  strings:
    $key_9653 = { c2 3b [2] b6 23 [2] f1 21 [2] b6 30 [2] f8 3c [2] f4 36 [2] e3 3d [2] f8 73 [2] c5 }

  condition:
    any of them
}