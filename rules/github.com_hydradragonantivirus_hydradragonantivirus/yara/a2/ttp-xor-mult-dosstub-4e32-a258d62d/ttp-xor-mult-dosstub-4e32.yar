rule TTP_XOR_MULT_DOSStub_4e32 {
  strings:
    $key_4e32 = { 1a 5a [2] 6e 42 [2] 29 40 [2] 6e 51 [2] 20 5d [2] 2c 57 [2] 3b 5c [2] 20 12 [2] 1d }

  condition:
    any of them
}