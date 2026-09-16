rule TTP_XOR_MULT_DOSStub_3ea5 {
  strings:
    $key_3ea5 = { 6a cd [2] 1e d5 [2] 59 d7 [2] 1e c6 [2] 50 ca [2] 5c c0 [2] 4b cb [2] 50 85 [2] 6d }

  condition:
    any of them
}