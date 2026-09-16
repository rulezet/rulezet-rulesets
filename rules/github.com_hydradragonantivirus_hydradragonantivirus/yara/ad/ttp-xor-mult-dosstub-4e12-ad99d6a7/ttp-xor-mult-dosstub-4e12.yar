rule TTP_XOR_MULT_DOSStub_4e12 {
  strings:
    $key_4e12 = { 1a 7a [2] 6e 62 [2] 29 60 [2] 6e 71 [2] 20 7d [2] 2c 77 [2] 3b 7c [2] 20 32 [2] 1d }

  condition:
    any of them
}