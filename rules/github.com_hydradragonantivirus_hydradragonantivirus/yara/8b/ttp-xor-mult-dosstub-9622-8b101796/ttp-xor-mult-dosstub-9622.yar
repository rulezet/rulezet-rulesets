rule TTP_XOR_MULT_DOSStub_9622 {
  strings:
    $key_9622 = { c2 4a [2] b6 52 [2] f1 50 [2] b6 41 [2] f8 4d [2] f4 47 [2] e3 4c [2] f8 02 [2] c5 }

  condition:
    any of them
}