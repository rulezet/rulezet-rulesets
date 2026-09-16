rule TTP_XOR_MULT_DOSStub_d523 {
  strings:
    $key_d523 = { 81 4b [2] f5 53 [2] b2 51 [2] f5 40 [2] bb 4c [2] b7 46 [2] a0 4d [2] bb 03 [2] 86 }

  condition:
    any of them
}