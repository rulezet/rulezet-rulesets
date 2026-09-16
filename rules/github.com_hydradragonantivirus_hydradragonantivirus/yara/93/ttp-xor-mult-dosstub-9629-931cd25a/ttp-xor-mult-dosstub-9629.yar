rule TTP_XOR_MULT_DOSStub_9629 {
  strings:
    $key_9629 = { c2 41 [2] b6 59 [2] f1 5b [2] b6 4a [2] f8 46 [2] f4 4c [2] e3 47 [2] f8 09 [2] c5 }

  condition:
    any of them
}