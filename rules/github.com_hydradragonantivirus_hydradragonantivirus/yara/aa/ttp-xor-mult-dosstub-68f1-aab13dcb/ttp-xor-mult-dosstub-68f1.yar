rule TTP_XOR_MULT_DOSStub_68f1 {
  strings:
    $key_68f1 = { 3c 99 [2] 48 81 [2] 0f 83 [2] 48 92 [2] 06 9e [2] 0a 94 [2] 1d 9f [2] 06 d1 [2] 3b }

  condition:
    any of them
}