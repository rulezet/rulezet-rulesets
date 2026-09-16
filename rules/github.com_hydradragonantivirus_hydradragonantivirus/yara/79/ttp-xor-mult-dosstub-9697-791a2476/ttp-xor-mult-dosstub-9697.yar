rule TTP_XOR_MULT_DOSStub_9697 {
  strings:
    $key_9697 = { c2 ff [2] b6 e7 [2] f1 e5 [2] b6 f4 [2] f8 f8 [2] f4 f2 [2] e3 f9 [2] f8 b7 [2] c5 }

  condition:
    any of them
}