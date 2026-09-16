rule TTP_XOR_MULT_DOSStub_4e59 {
  strings:
    $key_4e59 = { 1a 31 [2] 6e 29 [2] 29 2b [2] 6e 3a [2] 20 36 [2] 2c 3c [2] 3b 37 [2] 20 79 [2] 1d }

  condition:
    any of them
}