rule TTP_XOR_MULT_DOSStub_2c59 {
  strings:
    $key_2c59 = { 78 31 [2] 0c 29 [2] 4b 2b [2] 0c 3a [2] 42 36 [2] 4e 3c [2] 59 37 [2] 42 79 [2] 7f }

  condition:
    any of them
}