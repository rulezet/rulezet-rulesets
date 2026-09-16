rule TTP_XOR_MULT_DOSStub_4e33 {
  strings:
    $key_4e33 = { 1a 5b [2] 6e 43 [2] 29 41 [2] 6e 50 [2] 20 5c [2] 2c 56 [2] 3b 5d [2] 20 13 [2] 1d }

  condition:
    any of them
}