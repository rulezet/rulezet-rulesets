rule TTP_XOR_MULT_DOSStub_0749 {
  strings:
    $key_0749 = { 53 21 [2] 27 39 [2] 60 3b [2] 27 2a [2] 69 26 [2] 65 2c [2] 72 27 [2] 69 69 [2] 54 }

  condition:
    any of them
}