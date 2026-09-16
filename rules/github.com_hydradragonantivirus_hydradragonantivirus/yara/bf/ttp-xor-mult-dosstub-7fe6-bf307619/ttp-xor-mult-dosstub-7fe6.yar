rule TTP_XOR_MULT_DOSStub_7fe6 {
  strings:
    $key_7fe6 = { 2b 8e [2] 5f 96 [2] 18 94 [2] 5f 85 [2] 11 89 [2] 1d 83 [2] 0a 88 [2] 11 c6 [2] 2c }

  condition:
    any of them
}