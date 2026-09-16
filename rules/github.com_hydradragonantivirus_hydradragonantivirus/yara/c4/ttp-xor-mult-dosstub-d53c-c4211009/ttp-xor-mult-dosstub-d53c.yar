rule TTP_XOR_MULT_DOSStub_d53c {
  strings:
    $key_d53c = { 81 54 [2] f5 4c [2] b2 4e [2] f5 5f [2] bb 53 [2] b7 59 [2] a0 52 [2] bb 1c [2] 86 }

  condition:
    any of them
}