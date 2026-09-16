rule TTP_XOR_MULT_DOSStub_7e42 {
  strings:
    $key_7e42 = { 2a 2a [2] 5e 32 [2] 19 30 [2] 5e 21 [2] 10 2d [2] 1c 27 [2] 0b 2c [2] 10 62 [2] 2d }

  condition:
    any of them
}