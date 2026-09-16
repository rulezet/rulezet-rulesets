rule TTP_XOR_MULT_DOSStub_52a5 {
  strings:
    $key_52a5 = { 06 cd [2] 72 d5 [2] 35 d7 [2] 72 c6 [2] 3c ca [2] 30 c0 [2] 27 cb [2] 3c 85 [2] 01 }

  condition:
    any of them
}