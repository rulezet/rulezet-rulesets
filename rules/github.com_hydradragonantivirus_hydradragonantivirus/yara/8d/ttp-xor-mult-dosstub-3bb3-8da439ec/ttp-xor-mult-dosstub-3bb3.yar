rule TTP_XOR_MULT_DOSStub_3bb3 {
  strings:
    $key_3bb3 = { 6f db [2] 1b c3 [2] 5c c1 [2] 1b d0 [2] 55 dc [2] 59 d6 [2] 4e dd [2] 55 93 [2] 68 }

  condition:
    any of them
}