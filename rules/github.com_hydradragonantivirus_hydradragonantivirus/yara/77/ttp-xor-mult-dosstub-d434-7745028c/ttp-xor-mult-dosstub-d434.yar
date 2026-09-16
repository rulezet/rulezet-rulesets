rule TTP_XOR_MULT_DOSStub_d434 {
  strings:
    $key_d434 = { 80 5c [2] f4 44 [2] b3 46 [2] f4 57 [2] ba 5b [2] b6 51 [2] a1 5a [2] ba 14 [2] 87 }

  condition:
    any of them
}