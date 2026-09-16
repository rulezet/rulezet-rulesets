rule TTP_XOR_MULT_DOSStub_7044 {
  strings:
    $key_7044 = { 24 2c [2] 50 34 [2] 17 36 [2] 50 27 [2] 1e 2b [2] 12 21 [2] 05 2a [2] 1e 64 [2] 23 }

  condition:
    any of them
}