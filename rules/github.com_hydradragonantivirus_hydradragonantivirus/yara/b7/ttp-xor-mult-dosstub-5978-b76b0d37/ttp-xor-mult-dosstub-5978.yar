rule TTP_XOR_MULT_DOSStub_5978 {
  strings:
    $key_5978 = { 0d 10 [2] 79 08 [2] 3e 0a [2] 79 1b [2] 37 17 [2] 3b 1d [2] 2c 16 [2] 37 58 [2] 0a }

  condition:
    any of them
}