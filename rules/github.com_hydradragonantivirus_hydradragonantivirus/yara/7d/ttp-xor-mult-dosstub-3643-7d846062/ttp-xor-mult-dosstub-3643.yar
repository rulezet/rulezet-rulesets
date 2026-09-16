rule TTP_XOR_MULT_DOSStub_3643 {
  strings:
    $key_3643 = { 62 2b [2] 16 33 [2] 51 31 [2] 16 20 [2] 58 2c [2] 54 26 [2] 43 2d [2] 58 63 [2] 65 }

  condition:
    any of them
}