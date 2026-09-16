rule TTP_XOR_MULT_DOSStub_d402 {
  strings:
    $key_d402 = { 80 6a [2] f4 72 [2] b3 70 [2] f4 61 [2] ba 6d [2] b6 67 [2] a1 6c [2] ba 22 [2] 87 }

  condition:
    any of them
}