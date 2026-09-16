rule TTP_XOR_MULT_DOSStub_6ca5 {
  strings:
    $key_6ca5 = { 38 cd [2] 4c d5 [2] 0b d7 [2] 4c c6 [2] 02 ca [2] 0e c0 [2] 19 cb [2] 02 85 [2] 3f }

  condition:
    any of them
}