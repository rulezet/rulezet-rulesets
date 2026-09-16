rule TTP_XOR_MULT_DOSStub_5132 {
  strings:
    $key_5132 = { 05 5a [2] 71 42 [2] 36 40 [2] 71 51 [2] 3f 5d [2] 33 57 [2] 24 5c [2] 3f 12 [2] 02 }

  condition:
    any of them
}