rule TTP_XOR_MULT_DOSStub_2c79 {
  strings:
    $key_2c79 = { 78 11 [2] 0c 09 [2] 4b 0b [2] 0c 1a [2] 42 16 [2] 4e 1c [2] 59 17 [2] 42 59 [2] 7f }

  condition:
    any of them
}