rule TTP_XOR_MULT_DOSStub_2ba5 {
  strings:
    $key_2ba5 = { 7f cd [2] 0b d5 [2] 4c d7 [2] 0b c6 [2] 45 ca [2] 49 c0 [2] 5e cb [2] 45 85 [2] 78 }

  condition:
    any of them
}