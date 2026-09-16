rule TTP_XOR_MULT_DOSStub_1bb4 {
  strings:
    $key_1bb4 = { 4f dc [2] 3b c4 [2] 7c c6 [2] 3b d7 [2] 75 db [2] 79 d1 [2] 6e da [2] 75 94 [2] 48 }

  condition:
    any of them
}