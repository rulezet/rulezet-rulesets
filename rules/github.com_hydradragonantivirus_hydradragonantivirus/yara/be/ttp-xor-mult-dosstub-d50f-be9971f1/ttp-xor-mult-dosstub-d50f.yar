rule TTP_XOR_MULT_DOSStub_d50f {
  strings:
    $key_d50f = { 81 67 [2] f5 7f [2] b2 7d [2] f5 6c [2] bb 60 [2] b7 6a [2] a0 61 [2] bb 2f [2] 86 }

  condition:
    any of them
}