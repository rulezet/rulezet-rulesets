rule TTP_XOR_MULT_DOSStub_86a8 {
  strings:
    $key_86a8 = { d2 c0 [2] a6 d8 [2] e1 da [2] a6 cb [2] e8 c7 [2] e4 cd [2] f3 c6 [2] e8 88 [2] d5 }

  condition:
    any of them
}