rule TTP_XOR_MULT_DOSStub_96a5 {
  strings:
    $key_96a5 = { c2 cd [2] b6 d5 [2] f1 d7 [2] b6 c6 [2] f8 ca [2] f4 c0 [2] e3 cb [2] f8 85 [2] c5 }

  condition:
    any of them
}