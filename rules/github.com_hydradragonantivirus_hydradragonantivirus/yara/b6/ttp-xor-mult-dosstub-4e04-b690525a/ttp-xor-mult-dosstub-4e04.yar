rule TTP_XOR_MULT_DOSStub_4e04 {
  strings:
    $key_4e04 = { 1a 6c [2] 6e 74 [2] 29 76 [2] 6e 67 [2] 20 6b [2] 2c 61 [2] 3b 6a [2] 20 24 [2] 1d }

  condition:
    any of them
}