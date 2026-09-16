rule TTP_XOR_MULT_DOSStub_7243 {
  strings:
    $key_7243 = { 26 2b [2] 52 33 [2] 15 31 [2] 52 20 [2] 1c 2c [2] 10 26 [2] 07 2d [2] 1c 63 [2] 21 }

  condition:
    any of them
}