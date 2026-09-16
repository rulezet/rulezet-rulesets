rule TTP_XOR_MULT_DOSStub_2c15 {
  strings:
    $key_2c15 = { 78 7d [2] 0c 65 [2] 4b 67 [2] 0c 76 [2] 42 7a [2] 4e 70 [2] 59 7b [2] 42 35 [2] 7f }

  condition:
    any of them
}