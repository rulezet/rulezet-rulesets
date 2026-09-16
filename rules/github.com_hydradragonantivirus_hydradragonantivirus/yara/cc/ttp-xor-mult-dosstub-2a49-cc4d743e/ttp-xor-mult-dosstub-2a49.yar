rule TTP_XOR_MULT_DOSStub_2a49 {
  strings:
    $key_2a49 = { 7e 21 [2] 0a 39 [2] 4d 3b [2] 0a 2a [2] 44 26 [2] 48 2c [2] 5f 27 [2] 44 69 [2] 79 }

  condition:
    any of them
}