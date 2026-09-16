rule TTP_XOR_MULT_DOSStub_1ba5 {
  strings:
    $key_1ba5 = { 4f cd [2] 3b d5 [2] 7c d7 [2] 3b c6 [2] 75 ca [2] 79 c0 [2] 6e cb [2] 75 85 [2] 48 }

  condition:
    any of them
}