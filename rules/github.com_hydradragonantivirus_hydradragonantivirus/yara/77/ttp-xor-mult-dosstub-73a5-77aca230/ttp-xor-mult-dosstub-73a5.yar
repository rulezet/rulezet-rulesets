rule TTP_XOR_MULT_DOSStub_73a5 {
  strings:
    $key_73a5 = { 27 cd [2] 53 d5 [2] 14 d7 [2] 53 c6 [2] 1d ca [2] 11 c0 [2] 06 cb [2] 1d 85 [2] 20 }

  condition:
    any of them
}