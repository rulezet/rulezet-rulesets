rule TTP_XOR_MULT_DOSStub_4e73 {
  strings:
    $key_4e73 = { 1a 1b [2] 6e 03 [2] 29 01 [2] 6e 10 [2] 20 1c [2] 2c 16 [2] 3b 1d [2] 20 53 [2] 1d }

  condition:
    any of them
}