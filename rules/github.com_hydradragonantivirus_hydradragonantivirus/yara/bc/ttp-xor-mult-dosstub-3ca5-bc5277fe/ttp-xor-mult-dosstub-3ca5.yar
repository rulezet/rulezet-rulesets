rule TTP_XOR_MULT_DOSStub_3ca5 {
  strings:
    $key_3ca5 = { 68 cd [2] 1c d5 [2] 5b d7 [2] 1c c6 [2] 52 ca [2] 5e c0 [2] 49 cb [2] 52 85 [2] 6f }

  condition:
    any of them
}