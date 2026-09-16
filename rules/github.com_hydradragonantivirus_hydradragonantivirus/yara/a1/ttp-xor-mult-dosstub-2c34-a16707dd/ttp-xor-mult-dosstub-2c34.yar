rule TTP_XOR_MULT_DOSStub_2c34 {
  strings:
    $key_2c34 = { 78 5c [2] 0c 44 [2] 4b 46 [2] 0c 57 [2] 42 5b [2] 4e 51 [2] 59 5a [2] 42 14 [2] 7f }

  condition:
    any of them
}