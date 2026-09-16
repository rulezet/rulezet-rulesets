rule TTP_XOR_MULT_DOSStub_86a5 {
  strings:
    $key_86a5 = { d2 cd [2] a6 d5 [2] e1 d7 [2] a6 c6 [2] e8 ca [2] e4 c0 [2] f3 cb [2] e8 85 [2] d5 }

  condition:
    any of them
}