rule TTP_XOR_MULT_DOSStub_4e78 {
  strings:
    $key_4e78 = { 1a 10 [2] 6e 08 [2] 29 0a [2] 6e 1b [2] 20 17 [2] 2c 1d [2] 3b 16 [2] 20 58 [2] 1d }

  condition:
    any of them
}