rule TTP_XOR_MULT_DOSStub_d4e2 {
  strings:
    $key_d4e2 = { 80 8a [2] f4 92 [2] b3 90 [2] f4 81 [2] ba 8d [2] b6 87 [2] a1 8c [2] ba c2 [2] 87 }

  condition:
    any of them
}