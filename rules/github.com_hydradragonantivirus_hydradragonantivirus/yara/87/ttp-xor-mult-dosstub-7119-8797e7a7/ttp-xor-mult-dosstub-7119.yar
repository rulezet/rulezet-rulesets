rule TTP_XOR_MULT_DOSStub_7119 {
  strings:
    $key_7119 = { 25 71 [2] 51 69 [2] 16 6b [2] 51 7a [2] 1f 76 [2] 13 7c [2] 04 77 [2] 1f 39 [2] 22 }

  condition:
    any of them
}