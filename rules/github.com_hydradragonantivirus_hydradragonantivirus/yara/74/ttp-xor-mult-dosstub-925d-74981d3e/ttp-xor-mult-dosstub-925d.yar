rule TTP_XOR_MULT_DOSStub_925d {
  strings:
    $key_925d = { c6 35 [2] b2 2d [2] f5 2f [2] b2 3e [2] fc 32 [2] f0 38 [2] e7 33 [2] fc 7d [2] c1 }

  condition:
    any of them
}