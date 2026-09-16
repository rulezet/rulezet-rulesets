rule TTP_XOR_MULT_DOSStub_3a19 {
  strings:
    $key_3a19 = { 6e 71 [2] 1a 69 [2] 5d 6b [2] 1a 7a [2] 54 76 [2] 58 7c [2] 4f 77 [2] 54 39 [2] 69 }

  condition:
    any of them
}