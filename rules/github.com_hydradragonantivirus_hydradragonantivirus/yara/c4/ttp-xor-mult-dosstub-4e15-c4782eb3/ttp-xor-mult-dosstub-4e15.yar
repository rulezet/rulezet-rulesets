rule TTP_XOR_MULT_DOSStub_4e15 {
  strings:
    $key_4e15 = { 1a 7d [2] 6e 65 [2] 29 67 [2] 6e 76 [2] 20 7a [2] 2c 70 [2] 3b 7b [2] 20 35 [2] 1d }

  condition:
    any of them
}