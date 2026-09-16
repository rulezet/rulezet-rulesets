rule TTP_XOR_MULT_DOSStub_9271 {
  strings:
    $key_9271 = { c6 19 [2] b2 01 [2] f5 03 [2] b2 12 [2] fc 1e [2] f0 14 [2] e7 1f [2] fc 51 [2] c1 }

  condition:
    any of them
}