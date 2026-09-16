rule TTP_XOR_MULT_DOSStub_5ea9 {
  strings:
    $key_5ea9 = { 0a c1 [2] 7e d9 [2] 39 db [2] 7e ca [2] 30 c6 [2] 3c cc [2] 2b c7 [2] 30 89 [2] 0d }

  condition:
    any of them
}