rule TTP_XOR_MULT_DOSStub_92e3 {
  strings:
    $key_92e3 = { c6 8b [2] b2 93 [2] f5 91 [2] b2 80 [2] fc 8c [2] f0 86 [2] e7 8d [2] fc c3 [2] c1 }

  condition:
    any of them
}