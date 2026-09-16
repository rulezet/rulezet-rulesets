rule TTP_XOR_MULT_DOSStub_d54e {
  strings:
    $key_d54e = { 81 26 [2] f5 3e [2] b2 3c [2] f5 2d [2] bb 21 [2] b7 2b [2] a0 20 [2] bb 6e [2] 86 }

  condition:
    any of them
}