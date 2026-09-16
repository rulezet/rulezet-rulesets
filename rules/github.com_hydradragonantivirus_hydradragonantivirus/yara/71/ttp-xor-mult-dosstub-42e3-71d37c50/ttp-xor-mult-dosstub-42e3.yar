rule TTP_XOR_MULT_DOSStub_42e3 {
  strings:
    $key_42e3 = { 16 8b [2] 62 93 [2] 25 91 [2] 62 80 [2] 2c 8c [2] 20 86 [2] 37 8d [2] 2c c3 [2] 11 }

  condition:
    any of them
}