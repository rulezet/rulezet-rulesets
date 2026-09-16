rule TTP_XOR_MULT_DOSStub_d51f {
  strings:
    $key_d51f = { 81 77 [2] f5 6f [2] b2 6d [2] f5 7c [2] bb 70 [2] b7 7a [2] a0 71 [2] bb 3f [2] 86 }

  condition:
    any of them
}