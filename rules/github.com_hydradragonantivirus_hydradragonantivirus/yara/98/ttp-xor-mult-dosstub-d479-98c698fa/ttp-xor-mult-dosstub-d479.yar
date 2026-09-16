rule TTP_XOR_MULT_DOSStub_d479 {
  strings:
    $key_d479 = { 80 11 [2] f4 09 [2] b3 0b [2] f4 1a [2] ba 16 [2] b6 1c [2] a1 17 [2] ba 59 [2] 87 }

  condition:
    any of them
}