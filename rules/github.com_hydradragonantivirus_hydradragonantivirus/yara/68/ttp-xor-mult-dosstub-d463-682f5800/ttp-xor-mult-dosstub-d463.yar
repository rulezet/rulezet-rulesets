rule TTP_XOR_MULT_DOSStub_d463 {
  strings:
    $key_d463 = { 80 0b [2] f4 13 [2] b3 11 [2] f4 00 [2] ba 0c [2] b6 06 [2] a1 0d [2] ba 43 [2] 87 }

  condition:
    any of them
}