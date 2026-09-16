rule TTP_XOR_MULT_DOSStub_d4ae {
  strings:
    $key_d4ae = { 80 c6 [2] f4 de [2] b3 dc [2] f4 cd [2] ba c1 [2] b6 cb [2] a1 c0 [2] ba 8e [2] 87 }

  condition:
    any of them
}