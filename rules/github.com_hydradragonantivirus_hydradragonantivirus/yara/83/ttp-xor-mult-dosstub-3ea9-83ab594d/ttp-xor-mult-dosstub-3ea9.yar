rule TTP_XOR_MULT_DOSStub_3ea9 {
  strings:
    $key_3ea9 = { 6a c1 [2] 1e d9 [2] 59 db [2] 1e ca [2] 50 c6 [2] 5c cc [2] 4b c7 [2] 50 89 [2] 6d }

  condition:
    any of them
}