rule TTP_XOR_MULT_DOSStub_d6ae {
  strings:
    $key_d6ae = { 82 c6 [2] f6 de [2] b1 dc [2] f6 cd [2] b8 c1 [2] b4 cb [2] a3 c0 [2] b8 8e [2] 85 }

  condition:
    any of them
}