rule TTP_XOR_MULT_DOSStub_a7a5 {
  strings:
    $key_a7a5 = { f3 cd [2] 87 d5 [2] c0 d7 [2] 87 c6 [2] c9 ca [2] c5 c0 [2] d2 cb [2] c9 85 [2] f4 }

  condition:
    any of them
}