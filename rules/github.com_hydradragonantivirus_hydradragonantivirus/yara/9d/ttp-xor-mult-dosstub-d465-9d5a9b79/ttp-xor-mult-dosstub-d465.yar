rule TTP_XOR_MULT_DOSStub_d465 {
  strings:
    $key_d465 = { 80 0d [2] f4 15 [2] b3 17 [2] f4 06 [2] ba 0a [2] b6 00 [2] a1 0b [2] ba 45 [2] 87 }

  condition:
    any of them
}