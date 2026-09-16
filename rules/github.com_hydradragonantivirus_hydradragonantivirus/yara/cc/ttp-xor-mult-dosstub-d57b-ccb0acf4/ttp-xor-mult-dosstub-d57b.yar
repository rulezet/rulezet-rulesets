rule TTP_XOR_MULT_DOSStub_d57b {
  strings:
    $key_d57b = { 81 13 [2] f5 0b [2] b2 09 [2] f5 18 [2] bb 14 [2] b7 1e [2] a0 15 [2] bb 5b [2] 86 }

  condition:
    any of them
}