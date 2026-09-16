rule TTP_XOR_MULT_DOSStub_4e74 {
  strings:
    $key_4e74 = { 1a 1c [2] 6e 04 [2] 29 06 [2] 6e 17 [2] 20 1b [2] 2c 11 [2] 3b 1a [2] 20 54 [2] 1d }

  condition:
    any of them
}