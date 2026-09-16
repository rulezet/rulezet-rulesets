rule TTP_XOR_MULT_DOSStub_2c28 {
  strings:
    $key_2c28 = { 78 40 [2] 0c 58 [2] 4b 5a [2] 0c 4b [2] 42 47 [2] 4e 4d [2] 59 46 [2] 42 08 [2] 7f }

  condition:
    any of them
}