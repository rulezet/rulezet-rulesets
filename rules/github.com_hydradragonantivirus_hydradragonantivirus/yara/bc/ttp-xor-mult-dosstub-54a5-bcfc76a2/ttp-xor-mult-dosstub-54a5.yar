rule TTP_XOR_MULT_DOSStub_54a5 {
  strings:
    $key_54a5 = { 00 cd [2] 74 d5 [2] 33 d7 [2] 74 c6 [2] 3a ca [2] 36 c0 [2] 21 cb [2] 3a 85 [2] 07 }

  condition:
    any of them
}