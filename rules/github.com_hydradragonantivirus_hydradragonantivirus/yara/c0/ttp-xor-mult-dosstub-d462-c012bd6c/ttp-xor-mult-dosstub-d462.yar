rule TTP_XOR_MULT_DOSStub_d462 {
  strings:
    $key_d462 = { 80 0a [2] f4 12 [2] b3 10 [2] f4 01 [2] ba 0d [2] b6 07 [2] a1 0c [2] ba 42 [2] 87 }

  condition:
    any of them
}