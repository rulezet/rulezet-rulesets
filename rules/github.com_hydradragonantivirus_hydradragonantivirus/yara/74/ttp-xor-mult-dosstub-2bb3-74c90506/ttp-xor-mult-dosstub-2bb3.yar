rule TTP_XOR_MULT_DOSStub_2bb3 {
  strings:
    $key_2bb3 = { 7f db [2] 0b c3 [2] 4c c1 [2] 0b d0 [2] 45 dc [2] 49 d6 [2] 5e dd [2] 45 93 [2] 78 }

  condition:
    any of them
}