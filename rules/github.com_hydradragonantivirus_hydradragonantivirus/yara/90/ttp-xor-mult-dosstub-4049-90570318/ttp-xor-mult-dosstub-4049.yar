rule TTP_XOR_MULT_DOSStub_4049 {
  strings:
    $key_4049 = { 14 21 [2] 60 39 [2] 27 3b [2] 60 2a [2] 2e 26 [2] 22 2c [2] 35 27 [2] 2e 69 [2] 13 }

  condition:
    any of them
}