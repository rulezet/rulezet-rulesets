rule TTP_XOR_MULT_DOSStub_0149 {
  strings:
    $key_0149 = { 55 21 [2] 21 39 [2] 66 3b [2] 21 2a [2] 6f 26 [2] 63 2c [2] 74 27 [2] 6f 69 [2] 52 }

  condition:
    any of them
}