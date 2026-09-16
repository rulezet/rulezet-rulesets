rule TTP_XOR_MULT_DOSStub_d438 {
  strings:
    $key_d438 = { 80 50 [2] f4 48 [2] b3 4a [2] f4 5b [2] ba 57 [2] b6 5d [2] a1 56 [2] ba 18 [2] 87 }

  condition:
    any of them
}