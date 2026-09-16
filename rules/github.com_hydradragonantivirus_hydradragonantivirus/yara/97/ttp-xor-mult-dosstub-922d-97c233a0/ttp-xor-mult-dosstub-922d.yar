rule TTP_XOR_MULT_DOSStub_922d {
  strings:
    $key_922d = { c6 45 [2] b2 5d [2] f5 5f [2] b2 4e [2] fc 42 [2] f0 48 [2] e7 43 [2] fc 0d [2] c1 }

  condition:
    any of them
}