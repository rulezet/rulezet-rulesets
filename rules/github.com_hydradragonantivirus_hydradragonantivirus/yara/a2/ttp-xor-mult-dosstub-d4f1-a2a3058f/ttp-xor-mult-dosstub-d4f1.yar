rule TTP_XOR_MULT_DOSStub_d4f1 {
  strings:
    $key_d4f1 = { 80 99 [2] f4 81 [2] b3 83 [2] f4 92 [2] ba 9e [2] b6 94 [2] a1 9f [2] ba d1 [2] 87 }

  condition:
    any of them
}