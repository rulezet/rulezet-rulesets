rule TTP_XOR_MULT_DOSStub_5642 {
  strings:
    $key_5642 = { 02 2a [2] 76 32 [2] 31 30 [2] 76 21 [2] 38 2d [2] 34 27 [2] 23 2c [2] 38 62 [2] 05 }

  condition:
    any of them
}