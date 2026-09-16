rule TTP_XOR_MULT_DOSStub_2c54 {
  strings:
    $key_2c54 = { 78 3c [2] 0c 24 [2] 4b 26 [2] 0c 37 [2] 42 3b [2] 4e 31 [2] 59 3a [2] 42 74 [2] 7f }

  condition:
    any of them
}