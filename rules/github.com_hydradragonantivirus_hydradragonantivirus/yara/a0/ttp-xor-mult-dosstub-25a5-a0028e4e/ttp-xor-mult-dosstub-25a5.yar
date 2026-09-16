rule TTP_XOR_MULT_DOSStub_25a5 {
  strings:
    $key_25a5 = { 71 cd [2] 05 d5 [2] 42 d7 [2] 05 c6 [2] 4b ca [2] 47 c0 [2] 50 cb [2] 4b 85 [2] 76 }

  condition:
    any of them
}