rule TTP_XOR_MULT_DOSStub_d411 {
  strings:
    $key_d411 = { 80 79 [2] f4 61 [2] b3 63 [2] f4 72 [2] ba 7e [2] b6 74 [2] a1 7f [2] ba 31 [2] 87 }

  condition:
    any of them
}