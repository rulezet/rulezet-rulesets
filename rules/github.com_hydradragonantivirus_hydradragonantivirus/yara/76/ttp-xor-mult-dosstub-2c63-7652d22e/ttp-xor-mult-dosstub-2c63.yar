rule TTP_XOR_MULT_DOSStub_2c63 {
  strings:
    $key_2c63 = { 78 0b [2] 0c 13 [2] 4b 11 [2] 0c 00 [2] 42 0c [2] 4e 06 [2] 59 0d [2] 42 43 [2] 7f }

  condition:
    any of them
}