rule TTP_XOR_MULT_DOSStub_d454 {
  strings:
    $key_d454 = { 80 3c [2] f4 24 [2] b3 26 [2] f4 37 [2] ba 3b [2] b6 31 [2] a1 3a [2] ba 74 [2] 87 }

  condition:
    any of them
}