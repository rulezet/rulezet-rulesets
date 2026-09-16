rule TTP_XOR_MULT_DOSStub_a0a5 {
  strings:
    $key_a0a5 = { f4 cd [2] 80 d5 [2] c7 d7 [2] 80 c6 [2] ce ca [2] c2 c0 [2] d5 cb [2] ce 85 [2] f3 }

  condition:
    any of them
}