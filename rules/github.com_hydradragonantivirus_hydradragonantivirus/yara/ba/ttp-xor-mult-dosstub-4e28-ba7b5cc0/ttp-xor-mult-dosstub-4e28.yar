rule TTP_XOR_MULT_DOSStub_4e28 {
  strings:
    $key_4e28 = { 1a 40 [2] 6e 58 [2] 29 5a [2] 6e 4b [2] 20 47 [2] 2c 4d [2] 3b 46 [2] 20 08 [2] 1d }

  condition:
    any of them
}