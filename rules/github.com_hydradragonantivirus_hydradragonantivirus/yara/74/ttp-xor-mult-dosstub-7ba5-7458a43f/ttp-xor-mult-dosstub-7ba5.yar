rule TTP_XOR_MULT_DOSStub_7ba5 {
  strings:
    $key_7ba5 = { 2f cd [2] 5b d5 [2] 1c d7 [2] 5b c6 [2] 15 ca [2] 19 c0 [2] 0e cb [2] 15 85 [2] 28 }

  condition:
    any of them
}