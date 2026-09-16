rule TTP_XOR_MULT_DOSStub_75a8 {
  strings:
    $key_75a8 = { 21 c0 [2] 55 d8 [2] 12 da [2] 55 cb [2] 1b c7 [2] 17 cd [2] 00 c6 [2] 1b 88 [2] 26 }

  condition:
    any of them
}