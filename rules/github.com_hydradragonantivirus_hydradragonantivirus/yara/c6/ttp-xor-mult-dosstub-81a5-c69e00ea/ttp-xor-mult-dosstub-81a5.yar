rule TTP_XOR_MULT_DOSStub_81a5 {
  strings:
    $key_81a5 = { d5 cd [2] a1 d5 [2] e6 d7 [2] a1 c6 [2] ef ca [2] e3 c0 [2] f4 cb [2] ef 85 [2] d2 }

  condition:
    any of them
}