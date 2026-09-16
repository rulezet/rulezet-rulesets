rule TTP_XOR_MULT_DOSStub_d57c {
  strings:
    $key_d57c = { 81 14 [2] f5 0c [2] b2 0e [2] f5 1f [2] bb 13 [2] b7 19 [2] a0 12 [2] bb 5c [2] 86 }

  condition:
    any of them
}