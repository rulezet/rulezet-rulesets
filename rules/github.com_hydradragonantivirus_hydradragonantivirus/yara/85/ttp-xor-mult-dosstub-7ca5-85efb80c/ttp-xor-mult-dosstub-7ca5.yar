rule TTP_XOR_MULT_DOSStub_7ca5 {
  strings:
    $key_7ca5 = { 28 cd [2] 5c d5 [2] 1b d7 [2] 5c c6 [2] 12 ca [2] 1e c0 [2] 09 cb [2] 12 85 [2] 2f }

  condition:
    any of them
}