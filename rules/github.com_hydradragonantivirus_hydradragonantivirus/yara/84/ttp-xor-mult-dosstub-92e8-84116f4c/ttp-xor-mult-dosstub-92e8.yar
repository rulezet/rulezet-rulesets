rule TTP_XOR_MULT_DOSStub_92e8 {
  strings:
    $key_92e8 = { c6 80 [2] b2 98 [2] f5 9a [2] b2 8b [2] fc 87 [2] f0 8d [2] e7 86 [2] fc c8 [2] c1 }

  condition:
    any of them
}