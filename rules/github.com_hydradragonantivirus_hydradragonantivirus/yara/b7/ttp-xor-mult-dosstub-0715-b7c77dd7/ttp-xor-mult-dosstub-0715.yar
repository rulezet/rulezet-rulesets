rule TTP_XOR_MULT_DOSStub_0715 {
  strings:
    $key_0715 = { 53 7d [2] 27 65 [2] 60 67 [2] 27 76 [2] 69 7a [2] 65 70 [2] 72 7b [2] 69 35 [2] 54 }

  condition:
    any of them
}