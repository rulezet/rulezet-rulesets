rule TTP_XOR_MULT_DOSStub_94f0 {
  strings:
    $key_94f0 = { c0 98 [2] b4 80 [2] f3 82 [2] b4 93 [2] fa 9f [2] f6 95 [2] e1 9e [2] fa d0 [2] c7 }

  condition:
    any of them
}