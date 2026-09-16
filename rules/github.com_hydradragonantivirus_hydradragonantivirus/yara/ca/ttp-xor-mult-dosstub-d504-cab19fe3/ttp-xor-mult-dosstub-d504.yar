rule TTP_XOR_MULT_DOSStub_d504 {
  strings:
    $key_d504 = { 81 6c [2] f5 74 [2] b2 76 [2] f5 67 [2] bb 6b [2] b7 61 [2] a0 6a [2] bb 24 [2] 86 }

  condition:
    any of them
}