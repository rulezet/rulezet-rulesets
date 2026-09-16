rule TTP_XOR_MULT_DOSStub_d55b {
  strings:
    $key_d55b = { 81 33 [2] f5 2b [2] b2 29 [2] f5 38 [2] bb 34 [2] b7 3e [2] a0 35 [2] bb 7b [2] 86 }

  condition:
    any of them
}