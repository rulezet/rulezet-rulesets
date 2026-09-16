rule TTP_XOR_MULT_DOSStub_a1a8 {
  strings:
    $key_a1a8 = { f5 c0 [2] 81 d8 [2] c6 da [2] 81 cb [2] cf c7 [2] c3 cd [2] d4 c6 [2] cf 88 [2] f2 }

  condition:
    any of them
}