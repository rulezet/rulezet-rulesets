rule TTP_XOR_MULT_DOSStub_5965 {
  strings:
    $key_5965 = { 0d 0d [2] 79 15 [2] 3e 17 [2] 79 06 [2] 37 0a [2] 3b 00 [2] 2c 0b [2] 37 45 [2] 0a }

  condition:
    any of them
}