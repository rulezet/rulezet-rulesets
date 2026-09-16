rule TTP_XOR_MULT_DOSStub_d417 {
  strings:
    $key_d417 = { 80 7f [2] f4 67 [2] b3 65 [2] f4 74 [2] ba 78 [2] b6 72 [2] a1 79 [2] ba 37 [2] 87 }

  condition:
    any of them
}