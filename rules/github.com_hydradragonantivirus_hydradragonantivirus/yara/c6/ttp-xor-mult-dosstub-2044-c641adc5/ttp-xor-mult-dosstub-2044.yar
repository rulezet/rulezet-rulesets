rule TTP_XOR_MULT_DOSStub_2044 {
  strings:
    $key_2044 = { 74 2c [2] 00 34 [2] 47 36 [2] 00 27 [2] 4e 2b [2] 42 21 [2] 55 2a [2] 4e 64 [2] 73 }

  condition:
    any of them
}