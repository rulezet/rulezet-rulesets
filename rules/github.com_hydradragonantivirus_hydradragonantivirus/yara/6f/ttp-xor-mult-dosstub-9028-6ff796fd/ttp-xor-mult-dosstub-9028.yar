rule TTP_XOR_MULT_DOSStub_9028 {
  strings:
    $key_9028 = { c4 40 [2] b0 58 [2] f7 5a [2] b0 4b [2] fe 47 [2] f2 4d [2] e5 46 [2] fe 08 [2] c3 }

  condition:
    any of them
}