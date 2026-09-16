rule TTP_XOR_MULT_DOSStub_4108 {
  strings:
    $key_4108 = { 15 60 [2] 61 78 [2] 26 7a [2] 61 6b [2] 2f 67 [2] 23 6d [2] 34 66 [2] 2f 28 [2] 12 }

  condition:
    any of them
}