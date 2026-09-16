rule TTP_XOR_MULT_DOSStub_77a8 {
  strings:
    $key_77a8 = { 23 c0 [2] 57 d8 [2] 10 da [2] 57 cb [2] 19 c7 [2] 15 cd [2] 02 c6 [2] 19 88 [2] 24 }

  condition:
    any of them
}