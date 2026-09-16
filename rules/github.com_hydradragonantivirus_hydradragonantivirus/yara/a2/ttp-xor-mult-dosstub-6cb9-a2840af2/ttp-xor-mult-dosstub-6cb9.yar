rule TTP_XOR_MULT_DOSStub_6cb9 {
  strings:
    $key_6cb9 = { 38 d1 [2] 4c c9 [2] 0b cb [2] 4c da [2] 02 d6 [2] 0e dc [2] 19 d7 [2] 02 99 [2] 3f }

  condition:
    any of them
}