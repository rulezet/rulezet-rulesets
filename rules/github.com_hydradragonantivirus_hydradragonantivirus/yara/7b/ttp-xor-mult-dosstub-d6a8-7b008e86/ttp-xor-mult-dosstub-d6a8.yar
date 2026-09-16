rule TTP_XOR_MULT_DOSStub_d6a8 {
  strings:
    $key_d6a8 = { 82 c0 [2] f6 d8 [2] b1 da [2] f6 cb [2] b8 c7 [2] b4 cd [2] a3 c6 [2] b8 88 [2] 85 }

  condition:
    any of them
}