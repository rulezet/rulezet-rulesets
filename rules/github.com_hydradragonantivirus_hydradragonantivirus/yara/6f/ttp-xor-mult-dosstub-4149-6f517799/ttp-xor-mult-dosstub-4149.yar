rule TTP_XOR_MULT_DOSStub_4149 {
  strings:
    $key_4149 = { 15 21 [2] 61 39 [2] 26 3b [2] 61 2a [2] 2f 26 [2] 23 2c [2] 34 27 [2] 2f 69 [2] 12 }

  condition:
    any of them
}