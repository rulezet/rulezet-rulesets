rule TTP_XOR_MULT_DOSStub_5044 {
  strings:
    $key_5044 = { 04 2c [2] 70 34 [2] 37 36 [2] 70 27 [2] 3e 2b [2] 32 21 [2] 25 2a [2] 3e 64 [2] 03 }

  condition:
    any of them
}