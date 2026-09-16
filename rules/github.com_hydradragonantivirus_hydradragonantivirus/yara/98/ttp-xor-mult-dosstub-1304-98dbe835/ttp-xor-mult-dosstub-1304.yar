rule TTP_XOR_MULT_DOSStub_1304 {
  strings:
    $key_1304 = { 47 6c [2] 33 74 [2] 74 76 [2] 33 67 [2] 7d 6b [2] 71 61 [2] 66 6a [2] 7d 24 [2] 40 }

  condition:
    any of them
}