rule TTP_XOR_MULT_DOSStub_d451 {
  strings:
    $key_d451 = { 80 39 [2] f4 21 [2] b3 23 [2] f4 32 [2] ba 3e [2] b6 34 [2] a1 3f [2] ba 71 [2] 87 }

  condition:
    any of them
}