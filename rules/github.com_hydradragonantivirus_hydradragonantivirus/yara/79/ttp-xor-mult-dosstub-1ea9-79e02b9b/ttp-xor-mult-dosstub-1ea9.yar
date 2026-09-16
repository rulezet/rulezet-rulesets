rule TTP_XOR_MULT_DOSStub_1ea9 {
  strings:
    $key_1ea9 = { 4a c1 [2] 3e d9 [2] 79 db [2] 3e ca [2] 70 c6 [2] 7c cc [2] 6b c7 [2] 70 89 [2] 4d }

  condition:
    any of them
}