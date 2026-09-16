rule TTP_XOR_MULT_DOSStub_6bb4 {
  strings:
    $key_6bb4 = { 3f dc [2] 4b c4 [2] 0c c6 [2] 4b d7 [2] 05 db [2] 09 d1 [2] 1e da [2] 05 94 [2] 38 }

  condition:
    any of them
}