rule TTP_XOR_MULT_DOSStub_d4f6 {
  strings:
    $key_d4f6 = { 80 9e [2] f4 86 [2] b3 84 [2] f4 95 [2] ba 99 [2] b6 93 [2] a1 98 [2] ba d6 [2] 87 }

  condition:
    any of them
}