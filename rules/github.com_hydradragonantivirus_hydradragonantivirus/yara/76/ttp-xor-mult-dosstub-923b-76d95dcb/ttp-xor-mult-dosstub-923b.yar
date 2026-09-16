rule TTP_XOR_MULT_DOSStub_923b {
  strings:
    $key_923b = { c6 53 [2] b2 4b [2] f5 49 [2] b2 58 [2] fc 54 [2] f0 5e [2] e7 55 [2] fc 1b [2] c1 }

  condition:
    any of them
}