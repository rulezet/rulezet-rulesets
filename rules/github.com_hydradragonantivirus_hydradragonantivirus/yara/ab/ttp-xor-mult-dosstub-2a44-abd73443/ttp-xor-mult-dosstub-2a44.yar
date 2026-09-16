rule TTP_XOR_MULT_DOSStub_2a44 {
  strings:
    $key_2a44 = { 7e 2c [2] 0a 34 [2] 4d 36 [2] 0a 27 [2] 44 2b [2] 48 21 [2] 5f 2a [2] 44 64 [2] 79 }

  condition:
    any of them
}