rule TTP_XOR_MULT_DOSStub_4114 {
  strings:
    $key_4114 = { 15 7c [2] 61 64 [2] 26 66 [2] 61 77 [2] 2f 7b [2] 23 71 [2] 34 7a [2] 2f 34 [2] 12 }

  condition:
    any of them
}