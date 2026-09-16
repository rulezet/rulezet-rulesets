rule TTP_XOR_MULT_DOSStub_9678 {
  strings:
    $key_9678 = { c2 10 [2] b6 08 [2] f1 0a [2] b6 1b [2] f8 17 [2] f4 1d [2] e3 16 [2] f8 58 [2] c5 }

  condition:
    any of them
}