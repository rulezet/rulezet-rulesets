rule TTP_XOR_MULT_DOSStub_5119 {
  strings:
    $key_5119 = { 05 71 [2] 71 69 [2] 36 6b [2] 71 7a [2] 3f 76 [2] 33 7c [2] 24 77 [2] 3f 39 [2] 02 }

  condition:
    any of them
}