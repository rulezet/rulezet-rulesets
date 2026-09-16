rule TTP_XOR_MULT_DOSStub_d474 {
  strings:
    $key_d474 = { 80 1c [2] f4 04 [2] b3 06 [2] f4 17 [2] ba 1b [2] b6 11 [2] a1 1a [2] ba 54 [2] 87 }

  condition:
    any of them
}