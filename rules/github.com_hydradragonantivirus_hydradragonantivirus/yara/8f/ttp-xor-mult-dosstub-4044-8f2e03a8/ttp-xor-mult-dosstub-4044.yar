rule TTP_XOR_MULT_DOSStub_4044 {
  strings:
    $key_4044 = { 14 2c [2] 60 34 [2] 27 36 [2] 60 27 [2] 2e 2b [2] 22 21 [2] 35 2a [2] 2e 64 [2] 13 }

  condition:
    any of them
}