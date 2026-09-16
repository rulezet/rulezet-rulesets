rule TTP_XOR_MULT_DOSStub_0b44 {
  strings:
    $key_0b44 = { 5f 2c [2] 2b 34 [2] 6c 36 [2] 2b 27 [2] 65 2b [2] 69 21 [2] 7e 2a [2] 65 64 [2] 58 }

  condition:
    any of them
}