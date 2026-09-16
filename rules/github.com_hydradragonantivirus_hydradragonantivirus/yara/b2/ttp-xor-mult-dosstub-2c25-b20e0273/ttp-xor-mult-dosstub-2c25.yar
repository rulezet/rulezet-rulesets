rule TTP_XOR_MULT_DOSStub_2c25 {
  strings:
    $key_2c25 = { 78 4d [2] 0c 55 [2] 4b 57 [2] 0c 46 [2] 42 4a [2] 4e 40 [2] 59 4b [2] 42 05 [2] 7f }

  condition:
    any of them
}