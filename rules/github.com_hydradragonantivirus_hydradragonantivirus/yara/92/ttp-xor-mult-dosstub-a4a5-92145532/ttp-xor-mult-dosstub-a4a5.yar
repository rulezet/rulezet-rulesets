rule TTP_XOR_MULT_DOSStub_a4a5 {
  strings:
    $key_a4a5 = { f0 cd [2] 84 d5 [2] c3 d7 [2] 84 c6 [2] ca ca [2] c6 c0 [2] d1 cb [2] ca 85 [2] f7 }

  condition:
    any of them
}