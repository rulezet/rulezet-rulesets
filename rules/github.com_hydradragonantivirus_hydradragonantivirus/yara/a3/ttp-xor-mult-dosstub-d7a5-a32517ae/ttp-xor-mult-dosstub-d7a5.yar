rule TTP_XOR_MULT_DOSStub_d7a5 {
  strings:
    $key_d7a5 = { 83 cd [2] f7 d5 [2] b0 d7 [2] f7 c6 [2] b9 ca [2] b5 c0 [2] a2 cb [2] b9 85 [2] 84 }

  condition:
    any of them
}