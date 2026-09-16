rule TTP_XOR_MULT_DOSStub_d4e4 {
  strings:
    $key_d4e4 = { 80 8c [2] f4 94 [2] b3 96 [2] f4 87 [2] ba 8b [2] b6 81 [2] a1 8a [2] ba c4 [2] 87 }

  condition:
    any of them
}