rule TTP_XOR_MULT_DOSStub_1322 {
  strings:
    $key_1322 = { 47 4a [2] 33 52 [2] 74 50 [2] 33 41 [2] 7d 4d [2] 71 47 [2] 66 4c [2] 7d 02 [2] 40 }

  condition:
    any of them
}