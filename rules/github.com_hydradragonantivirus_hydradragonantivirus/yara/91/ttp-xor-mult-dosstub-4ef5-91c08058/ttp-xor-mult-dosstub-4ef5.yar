rule TTP_XOR_MULT_DOSStub_4ef5 {
  strings:
    $key_4ef5 = { 1a 9d [2] 6e 85 [2] 29 87 [2] 6e 96 [2] 20 9a [2] 2c 90 [2] 3b 9b [2] 20 d5 [2] 1d }

  condition:
    any of them
}