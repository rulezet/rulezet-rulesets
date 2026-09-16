rule TTP_XOR_MULT_DOSStub_7409 {
  strings:
    $key_7409 = { 20 61 [2] 54 79 [2] 13 7b [2] 54 6a [2] 1a 66 [2] 16 6c [2] 01 67 [2] 1a 29 [2] 27 }

  condition:
    any of them
}