rule TTP_XOR_MULT_DOSStub_0e42 {
  strings:
    $key_0e42 = { 5a 2a [2] 2e 32 [2] 69 30 [2] 2e 21 [2] 60 2d [2] 6c 27 [2] 7b 2c [2] 60 62 [2] 5d }

  condition:
    any of them
}