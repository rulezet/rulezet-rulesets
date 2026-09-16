rule TTP_XOR_MULT_DOSStub_5cb9 {
  strings:
    $key_5cb9 = { 08 d1 [2] 7c c9 [2] 3b cb [2] 7c da [2] 32 d6 [2] 3e dc [2] 29 d7 [2] 32 99 [2] 0f }

  condition:
    any of them
}