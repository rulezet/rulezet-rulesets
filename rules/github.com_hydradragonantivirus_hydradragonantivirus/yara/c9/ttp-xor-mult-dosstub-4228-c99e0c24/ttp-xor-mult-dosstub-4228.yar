rule TTP_XOR_MULT_DOSStub_4228 {
  strings:
    $key_4228 = { 16 40 [2] 62 58 [2] 25 5a [2] 62 4b [2] 2c 47 [2] 20 4d [2] 37 46 [2] 2c 08 [2] 11 }

  condition:
    any of them
}