rule TTP_XOR_MULT_DOSStub_a1a5 {
  strings:
    $key_a1a5 = { f5 cd [2] 81 d5 [2] c6 d7 [2] 81 c6 [2] cf ca [2] c3 c0 [2] d4 cb [2] cf 85 [2] f2 }

  condition:
    any of them
}