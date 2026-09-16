rule TTP_XOR_MULT_DOSStub_4e71 {
  strings:
    $key_4e71 = { 1a 19 [2] 6e 01 [2] 29 03 [2] 6e 12 [2] 20 1e [2] 2c 14 [2] 3b 1f [2] 20 51 [2] 1d }

  condition:
    any of them
}