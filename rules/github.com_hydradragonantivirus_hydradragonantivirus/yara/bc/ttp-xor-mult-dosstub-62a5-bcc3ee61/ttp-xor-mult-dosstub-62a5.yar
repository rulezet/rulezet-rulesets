rule TTP_XOR_MULT_DOSStub_62a5 {
  strings:
    $key_62a5 = { 36 cd [2] 42 d5 [2] 05 d7 [2] 42 c6 [2] 0c ca [2] 00 c0 [2] 17 cb [2] 0c 85 [2] 31 }

  condition:
    any of them
}