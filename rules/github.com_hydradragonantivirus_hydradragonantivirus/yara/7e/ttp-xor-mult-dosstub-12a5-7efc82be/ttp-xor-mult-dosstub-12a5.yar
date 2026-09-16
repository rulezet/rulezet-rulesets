rule TTP_XOR_MULT_DOSStub_12a5 {
  strings:
    $key_12a5 = { 46 cd [2] 32 d5 [2] 75 d7 [2] 32 c6 [2] 7c ca [2] 70 c0 [2] 67 cb [2] 7c 85 [2] 41 }

  condition:
    any of them
}