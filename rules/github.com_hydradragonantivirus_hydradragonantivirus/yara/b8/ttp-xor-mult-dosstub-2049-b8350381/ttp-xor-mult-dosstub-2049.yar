rule TTP_XOR_MULT_DOSStub_2049 {
  strings:
    $key_2049 = { 74 21 [2] 00 39 [2] 47 3b [2] 00 2a [2] 4e 26 [2] 42 2c [2] 55 27 [2] 4e 69 [2] 73 }

  condition:
    any of them
}