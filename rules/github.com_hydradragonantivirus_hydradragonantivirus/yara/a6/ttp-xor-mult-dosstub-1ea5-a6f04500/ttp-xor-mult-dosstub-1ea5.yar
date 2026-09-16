rule TTP_XOR_MULT_DOSStub_1ea5 {
  strings:
    $key_1ea5 = { 4a cd [2] 3e d5 [2] 79 d7 [2] 3e c6 [2] 70 ca [2] 7c c0 [2] 6b cb [2] 70 85 [2] 4d }

  condition:
    any of them
}