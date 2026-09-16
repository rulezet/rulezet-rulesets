rule TTP_XOR_MULT_DOSStub_51e4 {
  strings:
    $key_51e4 = { 05 8c [2] 71 94 [2] 36 96 [2] 71 87 [2] 3f 8b [2] 33 81 [2] 24 8a [2] 3f c4 [2] 02 }

  condition:
    any of them
}