rule TTP_XOR_MULT_DOSStub_d525 {
  strings:
    $key_d525 = { 81 4d [2] f5 55 [2] b2 57 [2] f5 46 [2] bb 4a [2] b7 40 [2] a0 4b [2] bb 05 [2] 86 }

  condition:
    any of them
}