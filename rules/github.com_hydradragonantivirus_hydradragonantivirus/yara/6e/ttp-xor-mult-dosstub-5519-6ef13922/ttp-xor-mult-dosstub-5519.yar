rule TTP_XOR_MULT_DOSStub_5519 {
  strings:
    $key_5519 = { 01 71 [2] 75 69 [2] 32 6b [2] 75 7a [2] 3b 76 [2] 37 7c [2] 20 77 [2] 3b 39 [2] 06 }

  condition:
    any of them
}