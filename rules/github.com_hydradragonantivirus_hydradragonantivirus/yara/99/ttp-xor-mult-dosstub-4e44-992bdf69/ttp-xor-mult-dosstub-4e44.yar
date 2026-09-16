rule TTP_XOR_MULT_DOSStub_4e44 {
  strings:
    $key_4e44 = { 1a 2c [2] 6e 34 [2] 29 36 [2] 6e 27 [2] 20 2b [2] 2c 21 [2] 3b 2a [2] 20 64 [2] 1d }

  condition:
    any of them
}