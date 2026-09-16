rule TTP_XOR_MULT_DOSStub_d426 {
  strings:
    $key_d426 = { 80 4e [2] f4 56 [2] b3 54 [2] f4 45 [2] ba 49 [2] b6 43 [2] a1 48 [2] ba 06 [2] 87 }

  condition:
    any of them
}