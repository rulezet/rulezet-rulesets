rule TTP_XOR_MULT_DOSStub_d8a8 {
  strings:
    $key_d8a8 = { 8c c0 [2] f8 d8 [2] bf da [2] f8 cb [2] b6 c7 [2] ba cd [2] ad c6 [2] b6 88 [2] 8b }

  condition:
    any of them
}