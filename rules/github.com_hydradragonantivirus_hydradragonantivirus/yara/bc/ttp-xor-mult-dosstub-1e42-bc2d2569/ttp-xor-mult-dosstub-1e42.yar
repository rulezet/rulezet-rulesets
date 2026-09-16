rule TTP_XOR_MULT_DOSStub_1e42 {
  strings:
    $key_1e42 = { 4a 2a [2] 3e 32 [2] 79 30 [2] 3e 21 [2] 70 2d [2] 7c 27 [2] 6b 2c [2] 70 62 [2] 4d }

  condition:
    any of them
}