rule TTP_XOR_MULT_DOSStub_5a49 {
  strings:
    $key_5a49 = { 0e 21 [2] 7a 39 [2] 3d 3b [2] 7a 2a [2] 34 26 [2] 38 2c [2] 2f 27 [2] 34 69 [2] 09 }

  condition:
    any of them
}