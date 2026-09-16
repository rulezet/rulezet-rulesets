rule TTP_XOR_MULT_DOSStub_42e8 {
  strings:
    $key_42e8 = { 16 80 [2] 62 98 [2] 25 9a [2] 62 8b [2] 2c 87 [2] 20 8d [2] 37 86 [2] 2c c8 [2] 11 }

  condition:
    any of them
}