rule TTP_XOR_MULT_DOSStub_97a5 {
  strings:
    $key_97a5 = { c3 cd [2] b7 d5 [2] f0 d7 [2] b7 c6 [2] f9 ca [2] f5 c0 [2] e2 cb [2] f9 85 [2] c4 }

  condition:
    any of them
}