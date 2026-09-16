rule TTP_XOR_MULT_DOSStub_d47c {
  strings:
    $key_d47c = { 80 14 [2] f4 0c [2] b3 0e [2] f4 1f [2] ba 13 [2] b6 19 [2] a1 12 [2] ba 5c [2] 87 }

  condition:
    any of them
}