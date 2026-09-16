rule TTP_XOR_MULT_DOSStub_9062 {
  strings:
    $key_9062 = { c4 0a [2] b0 12 [2] f7 10 [2] b0 01 [2] fe 0d [2] f2 07 [2] e5 0c [2] fe 42 [2] c3 }

  condition:
    any of them
}