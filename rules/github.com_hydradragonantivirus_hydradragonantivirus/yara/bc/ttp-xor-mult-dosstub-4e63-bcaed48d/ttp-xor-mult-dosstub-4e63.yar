rule TTP_XOR_MULT_DOSStub_4e63 {
  strings:
    $key_4e63 = { 1a 0b [2] 6e 13 [2] 29 11 [2] 6e 00 [2] 20 0c [2] 2c 06 [2] 3b 0d [2] 20 43 [2] 1d }

  condition:
    any of them
}