rule TTP_XOR_MULT_DOSStub_9624 {
  strings:
    $key_9624 = { c2 4c [2] b6 54 [2] f1 56 [2] b6 47 [2] f8 4b [2] f4 41 [2] e3 4a [2] f8 04 [2] c5 }

  condition:
    any of them
}