rule TTP_XOR_MULT_DOSStub_7bb3 {
  strings:
    $key_7bb3 = { 2f db [2] 5b c3 [2] 1c c1 [2] 5b d0 [2] 15 dc [2] 19 d6 [2] 0e dd [2] 15 93 [2] 28 }

  condition:
    any of them
}