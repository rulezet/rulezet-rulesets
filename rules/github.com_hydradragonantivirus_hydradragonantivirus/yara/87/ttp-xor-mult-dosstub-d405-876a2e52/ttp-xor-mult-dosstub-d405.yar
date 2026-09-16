rule TTP_XOR_MULT_DOSStub_d405 {
  strings:
    $key_d405 = { 80 6d [2] f4 75 [2] b3 77 [2] f4 66 [2] ba 6a [2] b6 60 [2] a1 6b [2] ba 25 [2] 87 }

  condition:
    any of them
}