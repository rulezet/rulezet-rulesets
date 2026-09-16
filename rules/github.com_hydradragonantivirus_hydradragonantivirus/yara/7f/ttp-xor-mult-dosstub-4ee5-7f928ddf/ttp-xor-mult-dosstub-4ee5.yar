rule TTP_XOR_MULT_DOSStub_4ee5 {
  strings:
    $key_4ee5 = { 1a 8d [2] 6e 95 [2] 29 97 [2] 6e 86 [2] 20 8a [2] 2c 80 [2] 3b 8b [2] 20 c5 [2] 1d }

  condition:
    any of them
}