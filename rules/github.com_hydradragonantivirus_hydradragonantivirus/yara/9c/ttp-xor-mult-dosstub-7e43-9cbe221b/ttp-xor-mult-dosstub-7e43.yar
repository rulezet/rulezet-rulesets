rule TTP_XOR_MULT_DOSStub_7e43 {
  strings:
    $key_7e43 = { 2a 2b [2] 5e 33 [2] 19 31 [2] 5e 20 [2] 10 2c [2] 1c 26 [2] 0b 2d [2] 10 63 [2] 2d }

  condition:
    any of them
}