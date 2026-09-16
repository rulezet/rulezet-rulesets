rule TTP_XOR_MULT_DOSStub_5e43 {
  strings:
    $key_5e43 = { 0a 2b [2] 7e 33 [2] 39 31 [2] 7e 20 [2] 30 2c [2] 3c 26 [2] 2b 2d [2] 30 63 [2] 0d }

  condition:
    any of them
}