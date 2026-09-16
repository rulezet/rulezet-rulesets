rule TTP_XOR_MULT_DOSStub_920b {
  strings:
    $key_920b = { c6 63 [2] b2 7b [2] f5 79 [2] b2 68 [2] fc 64 [2] f0 6e [2] e7 65 [2] fc 2b [2] c1 }

  condition:
    any of them
}