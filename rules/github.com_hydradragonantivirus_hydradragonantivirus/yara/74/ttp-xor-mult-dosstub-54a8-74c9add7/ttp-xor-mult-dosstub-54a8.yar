rule TTP_XOR_MULT_DOSStub_54a8 {
  strings:
    $key_54a8 = { 00 c0 [2] 74 d8 [2] 33 da [2] 74 cb [2] 3a c7 [2] 36 cd [2] 21 c6 [2] 3a 88 [2] 07 }

  condition:
    any of them
}