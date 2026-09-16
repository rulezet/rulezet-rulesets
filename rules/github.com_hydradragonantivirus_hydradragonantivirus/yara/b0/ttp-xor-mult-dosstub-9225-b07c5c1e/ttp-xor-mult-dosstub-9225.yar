rule TTP_XOR_MULT_DOSStub_9225 {
  strings:
    $key_9225 = { c6 4d [2] b2 55 [2] f5 57 [2] b2 46 [2] fc 4a [2] f0 40 [2] e7 4b [2] fc 05 [2] c1 }

  condition:
    any of them
}