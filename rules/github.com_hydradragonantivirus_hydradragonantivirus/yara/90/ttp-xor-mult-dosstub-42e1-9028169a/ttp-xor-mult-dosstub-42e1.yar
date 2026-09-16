rule TTP_XOR_MULT_DOSStub_42e1 {
  strings:
    $key_42e1 = { 16 89 [2] 62 91 [2] 25 93 [2] 62 82 [2] 2c 8e [2] 20 84 [2] 37 8f [2] 2c c1 [2] 11 }

  condition:
    any of them
}