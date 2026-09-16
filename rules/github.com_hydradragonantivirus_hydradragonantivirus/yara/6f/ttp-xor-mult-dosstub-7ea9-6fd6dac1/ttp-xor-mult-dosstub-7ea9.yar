rule TTP_XOR_MULT_DOSStub_7ea9 {
  strings:
    $key_7ea9 = { 2a c1 [2] 5e d9 [2] 19 db [2] 5e ca [2] 10 c6 [2] 1c cc [2] 0b c7 [2] 10 89 [2] 2d }

  condition:
    any of them
}