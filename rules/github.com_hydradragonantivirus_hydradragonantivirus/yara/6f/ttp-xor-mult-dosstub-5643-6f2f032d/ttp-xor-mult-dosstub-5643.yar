rule TTP_XOR_MULT_DOSStub_5643 {
  strings:
    $key_5643 = { 02 2b [2] 76 33 [2] 31 31 [2] 76 20 [2] 38 2c [2] 34 26 [2] 23 2d [2] 38 63 [2] 05 }

  condition:
    any of them
}