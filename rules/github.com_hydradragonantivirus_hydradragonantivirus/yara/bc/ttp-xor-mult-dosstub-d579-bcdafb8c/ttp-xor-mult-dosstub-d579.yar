rule TTP_XOR_MULT_DOSStub_d579 {
  strings:
    $key_d579 = { 81 11 [2] f5 09 [2] b2 0b [2] f5 1a [2] bb 16 [2] b7 1c [2] a0 17 [2] bb 59 [2] 86 }

  condition:
    any of them
}