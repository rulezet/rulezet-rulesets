rule TTP_XOR_MULT_DOSStub_5108 {
  strings:
    $key_5108 = { 05 60 [2] 71 78 [2] 36 7a [2] 71 6b [2] 3f 67 [2] 33 6d [2] 24 66 [2] 3f 28 [2] 02 }

  condition:
    any of them
}