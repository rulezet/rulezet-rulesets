rule TTP_XOR_MULT_DOSStub_42e5 {
  strings:
    $key_42e5 = { 16 8d [2] 62 95 [2] 25 97 [2] 62 86 [2] 2c 8a [2] 20 80 [2] 37 8b [2] 2c c5 [2] 11 }

  condition:
    any of them
}