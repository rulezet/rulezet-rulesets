rule TTP_XOR_MULT_DOSStub_d5f8 {
  strings:
    $key_d5f8 = { 81 90 [2] f5 88 [2] b2 8a [2] f5 9b [2] bb 97 [2] b7 9d [2] a0 96 [2] bb d8 [2] 86 }

  condition:
    any of them
}