rule TTP_XOR_MULT_DOSStub_4e68 {
  strings:
    $key_4e68 = { 1a 00 [2] 6e 18 [2] 29 1a [2] 6e 0b [2] 20 07 [2] 2c 0d [2] 3b 06 [2] 20 48 [2] 1d }

  condition:
    any of them
}