rule TTP_XOR_MULT_DOSStub_d437 {
  strings:
    $key_d437 = { 80 5f [2] f4 47 [2] b3 45 [2] f4 54 [2] ba 58 [2] b6 52 [2] a1 59 [2] ba 17 [2] 87 }

  condition:
    any of them
}