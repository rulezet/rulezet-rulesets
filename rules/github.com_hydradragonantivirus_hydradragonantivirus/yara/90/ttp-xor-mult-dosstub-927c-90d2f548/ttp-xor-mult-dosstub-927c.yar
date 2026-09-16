rule TTP_XOR_MULT_DOSStub_927c {
  strings:
    $key_927c = { c6 14 [2] b2 0c [2] f5 0e [2] b2 1f [2] fc 13 [2] f0 19 [2] e7 12 [2] fc 5c [2] c1 }

  condition:
    any of them
}