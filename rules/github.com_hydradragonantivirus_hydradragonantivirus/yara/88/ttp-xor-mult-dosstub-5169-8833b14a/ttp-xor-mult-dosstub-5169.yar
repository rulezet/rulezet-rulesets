rule TTP_XOR_MULT_DOSStub_5169 {
  strings:
    $key_5169 = { 05 01 [2] 71 19 [2] 36 1b [2] 71 0a [2] 3f 06 [2] 33 0c [2] 24 07 [2] 3f 49 [2] 02 }

  condition:
    any of them
}