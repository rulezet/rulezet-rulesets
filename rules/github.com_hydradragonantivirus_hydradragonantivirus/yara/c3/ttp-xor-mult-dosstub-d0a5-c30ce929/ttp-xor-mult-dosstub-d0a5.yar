rule TTP_XOR_MULT_DOSStub_d0a5 {
  strings:
    $key_d0a5 = { 84 cd [2] f0 d5 [2] b7 d7 [2] f0 c6 [2] be ca [2] b2 c0 [2] a5 cb [2] be 85 [2] 83 }

  condition:
    any of them
}