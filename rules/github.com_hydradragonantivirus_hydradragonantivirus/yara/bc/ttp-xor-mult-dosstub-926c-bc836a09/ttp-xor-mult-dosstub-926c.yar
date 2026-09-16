rule TTP_XOR_MULT_DOSStub_926c {
  strings:
    $key_926c = { c6 04 [2] b2 1c [2] f5 1e [2] b2 0f [2] fc 03 [2] f0 09 [2] e7 02 [2] fc 4c [2] c1 }

  condition:
    any of them
}