rule TTP_XOR_MULT_DOSStub_45a5 {
  strings:
    $key_45a5 = { 11 cd [2] 65 d5 [2] 22 d7 [2] 65 c6 [2] 2b ca [2] 27 c0 [2] 30 cb [2] 2b 85 [2] 16 }

  condition:
    any of them
}