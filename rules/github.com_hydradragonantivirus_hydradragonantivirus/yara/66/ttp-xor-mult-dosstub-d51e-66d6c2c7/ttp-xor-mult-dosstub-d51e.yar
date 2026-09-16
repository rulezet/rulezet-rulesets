rule TTP_XOR_MULT_DOSStub_d51e {
  strings:
    $key_d51e = { 81 76 [2] f5 6e [2] b2 6c [2] f5 7d [2] bb 71 [2] b7 7b [2] a0 70 [2] bb 3e [2] 86 }

  condition:
    any of them
}