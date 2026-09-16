rule TTP_XOR_MULT_DOSStub_1362 {
  strings:
    $key_1362 = { 47 0a [2] 33 12 [2] 74 10 [2] 33 01 [2] 7d 0d [2] 71 07 [2] 66 0c [2] 7d 42 [2] 40 }

  condition:
    any of them
}