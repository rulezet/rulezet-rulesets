rule TTP_XOR_MULT_DOSStub_d421 {
  strings:
    $key_d421 = { 80 49 [2] f4 51 [2] b3 53 [2] f4 42 [2] ba 4e [2] b6 44 [2] a1 4f [2] ba 01 [2] 87 }

  condition:
    any of them
}