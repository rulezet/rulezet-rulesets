rule TTP_XOR_MULT_DOSStub_4b49 {
  strings:
    $key_4b49 = { 1f 21 [2] 6b 39 [2] 2c 3b [2] 6b 2a [2] 25 26 [2] 29 2c [2] 3e 27 [2] 25 69 [2] 18 }

  condition:
    any of them
}