rule TTP_XOR_MULT_DOSStub_1a49 {
  strings:
    $key_1a49 = { 4e 21 [2] 3a 39 [2] 7d 3b [2] 3a 2a [2] 74 26 [2] 78 2c [2] 6f 27 [2] 74 69 [2] 49 }

  condition:
    any of them
}