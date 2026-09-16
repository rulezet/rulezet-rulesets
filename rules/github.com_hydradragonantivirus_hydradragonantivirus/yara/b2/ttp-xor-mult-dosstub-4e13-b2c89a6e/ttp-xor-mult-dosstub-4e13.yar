rule TTP_XOR_MULT_DOSStub_4e13 {
  strings:
    $key_4e13 = { 1a 7b [2] 6e 63 [2] 29 61 [2] 6e 70 [2] 20 7c [2] 2c 76 [2] 3b 7d [2] 20 33 [2] 1d }

  condition:
    any of them
}