rule TTP_XOR_MULT_DOSStub_9213 {
  strings:
    $key_9213 = { c6 7b [2] b2 63 [2] f5 61 [2] b2 70 [2] fc 7c [2] f0 76 [2] e7 7d [2] fc 33 [2] c1 }

  condition:
    any of them
}