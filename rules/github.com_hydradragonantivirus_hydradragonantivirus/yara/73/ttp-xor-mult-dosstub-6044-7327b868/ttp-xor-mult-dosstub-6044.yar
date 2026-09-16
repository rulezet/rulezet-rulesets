rule TTP_XOR_MULT_DOSStub_6044 {
  strings:
    $key_6044 = { 34 2c [2] 40 34 [2] 07 36 [2] 40 27 [2] 0e 2b [2] 02 21 [2] 15 2a [2] 0e 64 [2] 33 }

  condition:
    any of them
}