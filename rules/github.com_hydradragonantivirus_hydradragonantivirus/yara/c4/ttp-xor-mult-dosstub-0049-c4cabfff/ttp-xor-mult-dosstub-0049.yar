rule TTP_XOR_MULT_DOSStub_0049 {
  strings:
    $key_0049 = { 54 21 [2] 20 39 [2] 67 3b [2] 20 2a [2] 6e 26 [2] 62 2c [2] 75 27 [2] 6e 69 [2] 53 }

  condition:
    any of them
}