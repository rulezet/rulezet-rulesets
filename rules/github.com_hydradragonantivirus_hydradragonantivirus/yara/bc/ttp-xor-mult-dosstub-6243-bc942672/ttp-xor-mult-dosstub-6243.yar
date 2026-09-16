rule TTP_XOR_MULT_DOSStub_6243 {
  strings:
    $key_6243 = { 36 2b [2] 42 33 [2] 05 31 [2] 42 20 [2] 0c 2c [2] 00 26 [2] 17 2d [2] 0c 63 [2] 31 }

  condition:
    any of them
}