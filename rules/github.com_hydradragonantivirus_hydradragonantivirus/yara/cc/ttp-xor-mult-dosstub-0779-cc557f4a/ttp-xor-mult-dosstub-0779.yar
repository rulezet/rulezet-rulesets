rule TTP_XOR_MULT_DOSStub_0779 {
  strings:
    $key_0779 = { 53 11 [2] 27 09 [2] 60 0b [2] 27 1a [2] 69 16 [2] 65 1c [2] 72 17 [2] 69 59 [2] 54 }

  condition:
    any of them
}