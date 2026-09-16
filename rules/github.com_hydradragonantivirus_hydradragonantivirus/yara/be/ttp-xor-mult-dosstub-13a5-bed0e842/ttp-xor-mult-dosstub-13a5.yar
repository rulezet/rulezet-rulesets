rule TTP_XOR_MULT_DOSStub_13a5 {
  strings:
    $key_13a5 = { 47 cd [2] 33 d5 [2] 74 d7 [2] 33 c6 [2] 7d ca [2] 71 c0 [2] 66 cb [2] 7d 85 [2] 40 }

  condition:
    any of them
}