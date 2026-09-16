rule TTP_XOR_MULT_DOSStub_d4a8 {
  strings:
    $key_d4a8 = { 80 c0 [2] f4 d8 [2] b3 da [2] f4 cb [2] ba c7 [2] b6 cd [2] a1 c6 [2] ba 88 [2] 87 }

  condition:
    any of them
}