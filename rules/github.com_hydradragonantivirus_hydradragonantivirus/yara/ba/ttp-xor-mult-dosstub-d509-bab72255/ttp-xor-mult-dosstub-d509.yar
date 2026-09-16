rule TTP_XOR_MULT_DOSStub_d509 {
  strings:
    $key_d509 = { 81 61 [2] f5 79 [2] b2 7b [2] f5 6a [2] bb 66 [2] b7 6c [2] a0 67 [2] bb 29 [2] 86 }

  condition:
    any of them
}