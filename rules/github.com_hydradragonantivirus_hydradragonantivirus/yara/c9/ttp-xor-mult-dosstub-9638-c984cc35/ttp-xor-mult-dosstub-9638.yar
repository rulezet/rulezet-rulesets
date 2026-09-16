rule TTP_XOR_MULT_DOSStub_9638 {
  strings:
    $key_9638 = { c2 50 [2] b6 48 [2] f1 4a [2] b6 5b [2] f8 57 [2] f4 5d [2] e3 56 [2] f8 18 [2] c5 }

  condition:
    any of them
}