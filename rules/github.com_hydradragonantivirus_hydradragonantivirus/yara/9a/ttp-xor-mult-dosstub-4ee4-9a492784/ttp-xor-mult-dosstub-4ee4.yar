rule TTP_XOR_MULT_DOSStub_4ee4 {
  strings:
    $key_4ee4 = { 1a 8c [2] 6e 94 [2] 29 96 [2] 6e 87 [2] 20 8b [2] 2c 81 [2] 3b 8a [2] 20 c4 [2] 1d }

  condition:
    any of them
}