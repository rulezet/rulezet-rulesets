rule TTP_XOR_MULT_DOSStub_d56f {
  strings:
    $key_d56f = { 81 07 [2] f5 1f [2] b2 1d [2] f5 0c [2] bb 00 [2] b7 0a [2] a0 01 [2] bb 4f [2] 86 }

  condition:
    any of them
}