rule TTP_XOR_MULT_DOSStub_d4e6 {
  strings:
    $key_d4e6 = { 80 8e [2] f4 96 [2] b3 94 [2] f4 85 [2] ba 89 [2] b6 83 [2] a1 88 [2] ba c6 [2] 87 }

  condition:
    any of them
}