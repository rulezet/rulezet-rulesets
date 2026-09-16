rule TTP_XOR_MULT_DOSStub_1bb3 {
  strings:
    $key_1bb3 = { 4f db [2] 3b c3 [2] 7c c1 [2] 3b d0 [2] 75 dc [2] 79 d6 [2] 6e dd [2] 75 93 [2] 48 }

  condition:
    any of them
}