rule TTP_XOR_MULT_DOSStub_d425 {
  strings:
    $key_d425 = { 80 4d [2] f4 55 [2] b3 57 [2] f4 46 [2] ba 4a [2] b6 40 [2] a1 4b [2] ba 05 [2] 87 }

  condition:
    any of them
}