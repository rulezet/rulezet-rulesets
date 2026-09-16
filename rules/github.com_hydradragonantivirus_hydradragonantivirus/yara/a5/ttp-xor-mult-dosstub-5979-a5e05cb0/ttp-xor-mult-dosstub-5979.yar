rule TTP_XOR_MULT_DOSStub_5979 {
  strings:
    $key_5979 = { 0d 11 [2] 79 09 [2] 3e 0b [2] 79 1a [2] 37 16 [2] 3b 1c [2] 2c 17 [2] 37 59 [2] 0a }

  condition:
    any of them
}