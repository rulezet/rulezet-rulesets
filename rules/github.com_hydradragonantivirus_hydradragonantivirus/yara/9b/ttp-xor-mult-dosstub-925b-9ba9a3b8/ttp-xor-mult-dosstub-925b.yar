rule TTP_XOR_MULT_DOSStub_925b {
  strings:
    $key_925b = { c6 33 [2] b2 2b [2] f5 29 [2] b2 38 [2] fc 34 [2] f0 3e [2] e7 35 [2] fc 7b [2] c1 }

  condition:
    any of them
}