rule TTP_XOR_MULT_DOSStub_d57f {
  strings:
    $key_d57f = { 81 17 [2] f5 0f [2] b2 0d [2] f5 1c [2] bb 10 [2] b7 1a [2] a0 11 [2] bb 5f [2] 86 }

  condition:
    any of them
}