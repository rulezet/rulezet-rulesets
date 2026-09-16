rule TTP_XOR_MULT_DOSStub_7cb9 {
  strings:
    $key_7cb9 = { 28 d1 [2] 5c c9 [2] 1b cb [2] 5c da [2] 12 d6 [2] 1e dc [2] 09 d7 [2] 12 99 [2] 2f }

  condition:
    any of them
}