rule TTP_XOR_MULT_DOSStub_5205 {
  strings:
    $key_5205 = { 06 6d [2] 72 75 [2] 35 77 [2] 72 66 [2] 3c 6a [2] 30 60 [2] 27 6b [2] 3c 25 [2] 01 }

  condition:
    any of them
}