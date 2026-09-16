rule TTP_XOR_MULT_DOSStub_7ae6 {
  strings:
    $key_7ae6 = { 2e 8e [2] 5a 96 [2] 1d 94 [2] 5a 85 [2] 14 89 [2] 18 83 [2] 0f 88 [2] 14 c6 [2] 29 }

  condition:
    any of them
}