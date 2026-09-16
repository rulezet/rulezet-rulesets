rule TTP_XOR_MULT_DOSStub_2c74 {
  strings:
    $key_2c74 = { 78 1c [2] 0c 04 [2] 4b 06 [2] 0c 17 [2] 42 1b [2] 4e 11 [2] 59 1a [2] 42 54 [2] 7f }

  condition:
    any of them
}