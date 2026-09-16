rule TTP_XOR_MULT_DOSStub_03a5 {
  strings:
    $key_03a5 = { 57 cd [2] 23 d5 [2] 64 d7 [2] 23 c6 [2] 6d ca [2] 61 c0 [2] 76 cb [2] 6d 85 [2] 50 }

  condition:
    any of them
}