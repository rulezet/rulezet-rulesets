rule TTP_XOR_MULT_DOSStub_7b44 {
  strings:
    $key_7b44 = { 2f 2c [2] 5b 34 [2] 1c 36 [2] 5b 27 [2] 15 2b [2] 19 21 [2] 0e 2a [2] 15 64 [2] 28 }

  condition:
    any of them
}