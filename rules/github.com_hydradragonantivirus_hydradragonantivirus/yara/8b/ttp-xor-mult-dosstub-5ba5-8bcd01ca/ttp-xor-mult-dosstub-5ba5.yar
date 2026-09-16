rule TTP_XOR_MULT_DOSStub_5ba5 {
  strings:
    $key_5ba5 = { 0f cd [2] 7b d5 [2] 3c d7 [2] 7b c6 [2] 35 ca [2] 39 c0 [2] 2e cb [2] 35 85 [2] 08 }

  condition:
    any of them
}