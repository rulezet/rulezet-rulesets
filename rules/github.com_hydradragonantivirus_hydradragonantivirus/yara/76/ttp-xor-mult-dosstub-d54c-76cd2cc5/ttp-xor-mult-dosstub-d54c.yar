rule TTP_XOR_MULT_DOSStub_d54c {
  strings:
    $key_d54c = { 81 24 [2] f5 3c [2] b2 3e [2] f5 2f [2] bb 23 [2] b7 29 [2] a0 22 [2] bb 6c [2] 86 }

  condition:
    any of them
}