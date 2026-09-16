rule TTP_XOR_MULT_DOSStub_9223 {
  strings:
    $key_9223 = { c6 4b [2] b2 53 [2] f5 51 [2] b2 40 [2] fc 4c [2] f0 46 [2] e7 4d [2] fc 03 [2] c1 }

  condition:
    any of them
}