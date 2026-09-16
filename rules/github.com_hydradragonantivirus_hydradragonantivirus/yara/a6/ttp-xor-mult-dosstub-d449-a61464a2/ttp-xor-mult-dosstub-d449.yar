rule TTP_XOR_MULT_DOSStub_d449 {
  strings:
    $key_d449 = { 80 21 [2] f4 39 [2] b3 3b [2] f4 2a [2] ba 26 [2] b6 2c [2] a1 27 [2] ba 69 [2] 87 }

  condition:
    any of them
}