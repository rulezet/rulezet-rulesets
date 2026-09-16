rule TTP_XOR_MULT_DOSStub_925f {
  strings:
    $key_925f = { c6 37 [2] b2 2f [2] f5 2d [2] b2 3c [2] fc 30 [2] f0 3a [2] e7 31 [2] fc 7f [2] c1 }

  condition:
    any of them
}