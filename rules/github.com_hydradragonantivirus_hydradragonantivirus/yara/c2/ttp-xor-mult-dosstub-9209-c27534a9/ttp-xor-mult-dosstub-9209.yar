rule TTP_XOR_MULT_DOSStub_9209 {
  strings:
    $key_9209 = { c6 61 [2] b2 79 [2] f5 7b [2] b2 6a [2] fc 66 [2] f0 6c [2] e7 67 [2] fc 29 [2] c1 }

  condition:
    any of them
}