rule TTP_XOR_MULT_DOSStub_4e18 {
  strings:
    $key_4e18 = { 1a 70 [2] 6e 68 [2] 29 6a [2] 6e 7b [2] 20 77 [2] 2c 7d [2] 3b 76 [2] 20 38 [2] 1d }

  condition:
    any of them
}