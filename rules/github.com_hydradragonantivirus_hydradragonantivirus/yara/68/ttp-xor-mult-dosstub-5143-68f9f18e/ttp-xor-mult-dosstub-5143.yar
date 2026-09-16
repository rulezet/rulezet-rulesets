rule TTP_XOR_MULT_DOSStub_5143 {
  strings:
    $key_5143 = { 05 2b [2] 71 33 [2] 36 31 [2] 71 20 [2] 3f 2c [2] 33 26 [2] 24 2d [2] 3f 63 [2] 02 }

  condition:
    any of them
}