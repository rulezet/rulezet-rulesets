rule TTP_XOR_MULT_DOSStub_01e4 {
  strings:
    $key_01e4 = { 55 8c [2] 21 94 [2] 66 96 [2] 21 87 [2] 6f 8b [2] 63 81 [2] 74 8a [2] 6f c4 [2] 52 }

  condition:
    any of them
}