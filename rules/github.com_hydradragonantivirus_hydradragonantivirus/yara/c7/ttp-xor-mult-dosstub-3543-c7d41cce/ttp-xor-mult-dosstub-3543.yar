rule TTP_XOR_MULT_DOSStub_3543 {
  strings:
    $key_3543 = { 61 2b [2] 15 33 [2] 52 31 [2] 15 20 [2] 5b 2c [2] 57 26 [2] 40 2d [2] 5b 63 [2] 66 }

  condition:
    any of them
}