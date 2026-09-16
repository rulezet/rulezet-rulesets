rule TTP_XOR_MULT_DOSStub_5159 {
  strings:
    $key_5159 = { 05 31 [2] 71 29 [2] 36 2b [2] 71 3a [2] 3f 36 [2] 33 3c [2] 24 37 [2] 3f 79 [2] 02 }

  condition:
    any of them
}