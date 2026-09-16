rule TTP_XOR_MULT_DOSStub_42e6 {
  strings:
    $key_42e6 = { 16 8e [2] 62 96 [2] 25 94 [2] 62 85 [2] 2c 89 [2] 20 83 [2] 37 88 [2] 2c c6 [2] 11 }

  condition:
    any of them
}