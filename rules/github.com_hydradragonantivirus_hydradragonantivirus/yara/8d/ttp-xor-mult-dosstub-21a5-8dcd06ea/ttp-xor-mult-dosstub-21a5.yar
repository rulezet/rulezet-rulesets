rule TTP_XOR_MULT_DOSStub_21a5 {
  strings:
    $key_21a5 = { 75 cd [2] 01 d5 [2] 46 d7 [2] 01 c6 [2] 4f ca [2] 43 c0 [2] 54 cb [2] 4f 85 [2] 72 }

  condition:
    any of them
}