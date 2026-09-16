rule TTP_XOR_MULT_DOSStub_55a5 {
  strings:
    $key_55a5 = { 01 cd [2] 75 d5 [2] 32 d7 [2] 75 c6 [2] 3b ca [2] 37 c0 [2] 20 cb [2] 3b 85 [2] 06 }

  condition:
    any of them
}