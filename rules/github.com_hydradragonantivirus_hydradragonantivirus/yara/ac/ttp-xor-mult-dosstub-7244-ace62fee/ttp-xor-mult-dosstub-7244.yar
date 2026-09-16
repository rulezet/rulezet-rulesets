rule TTP_XOR_MULT_DOSStub_7244 {
  strings:
    $key_7244 = { 26 2c [2] 52 34 [2] 15 36 [2] 52 27 [2] 1c 2b [2] 10 21 [2] 07 2a [2] 1c 64 [2] 21 }

  condition:
    any of them
}