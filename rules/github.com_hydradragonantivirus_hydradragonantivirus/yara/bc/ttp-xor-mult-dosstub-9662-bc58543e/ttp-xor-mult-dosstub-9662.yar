rule TTP_XOR_MULT_DOSStub_9662 {
  strings:
    $key_9662 = { c2 0a [2] b6 12 [2] f1 10 [2] b6 01 [2] f8 0d [2] f4 07 [2] e3 0c [2] f8 42 [2] c5 }

  condition:
    any of them
}